// Copyright (c) 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package extension

import (
	"context"
	"fmt"

	extensionsconfig "github.com/gardener/gardener/extensions/pkg/apis/config"
	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	"github.com/gardener/gardener/extensions/pkg/util"
	v1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/component"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-registry-cache/pkg/apis/config"
	"github.com/gardener/gardener-extension-registry-cache/pkg/apis/registry/v1alpha1"
	"github.com/gardener/gardener-extension-registry-cache/pkg/component/registrycaches"
	"github.com/gardener/gardener-extension-registry-cache/pkg/component/registryconfigurationcleaner"
	"github.com/gardener/gardener-extension-registry-cache/pkg/constants"
	"github.com/gardener/gardener-extension-registry-cache/pkg/imagevector"
)

// NewActuator returns an actuator responsible for Extension resources.
func NewActuator(client client.Client, decoder runtime.Decoder, config config.Configuration) extension.Actuator {
	return &actuator{
		client:  client,
		decoder: decoder,
		config:  config,
	}
}

type actuator struct {
	client  client.Client
	decoder runtime.Decoder
	config  config.Configuration
}

// Reconcile the Extension resource.
func (a *actuator) Reconcile(ctx context.Context, _ logr.Logger, ex *extensionsv1alpha1.Extension) error {
	if ex.Spec.ProviderConfig == nil {
		return fmt.Errorf("providerConfig is required for the registry-cache extension")
	}

	registryConfig := &v1alpha1.RegistryConfig{}
	if _, _, err := a.decoder.Decode(ex.Spec.ProviderConfig.Raw, nil, registryConfig); err != nil {
		return fmt.Errorf("failed to decode provider config: %w", err)
	}

	// TODO: extension disablement has to be handled in the Delete func

	// Find caches to destroy
	if ex.Status.ProviderStatus != nil {
		registryStatus := &v1alpha1.RegistryStatus{}
		if _, _, err := a.decoder.Decode(ex.Status.ProviderStatus.Raw, nil, registryStatus); err != nil {
			return fmt.Errorf("failed to decode providerStatus of extension '%s': %w", client.ObjectKeyFromObject(ex), err)
		}

		existingUpstreams := sets.New[string]()
		for _, cache := range registryStatus.Caches {
			existingUpstreams.Insert(cache.Upstream)
		}

		desiredUpstreams := sets.New[string]()
		for _, cache := range registryConfig.Caches {
			desiredUpstreams.Insert(cache.Upstream)
		}

		upstreamsToDelete := existingUpstreams.Difference(desiredUpstreams)
		if upstreamsToDelete.Len() > 0 {
			for _, toDelete := range upstreamsToDelete {

				_ = &appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "kube-system",
					},
					Spec: appsv1.DaemonSetSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name:  "pause",
										Image: "registry.k8s.io/pause:3.7",
									},
								},
							},
						},
					},
				}
				// TODO: continue from here. Deploy DaemonSet.

				_ = toDelete
			}
		}
	}

	image, err := imagevector.ImageVector().FindImage("registry")
	if err != nil {
		return fmt.Errorf("failed to find registry image: %w", err)
	}

	namespace := ex.GetNamespace()
	registryCaches := registrycaches.New(a.client, namespace, registrycaches.Values{
		Image:  image.String(),
		Caches: registryConfig.Caches,
	})

	if err := registryCaches.Deploy(ctx); err != nil {
		return fmt.Errorf("failed to deploy the registry caches component: %w", err)
	}

	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return fmt.Errorf("failed to get cluster: %w", err)
	}

	// If the hibernation is enabled, don't try to fetch the registry cache endpoints from the Shoot cluster.
	if !v1beta1helper.HibernationIsEnabled(cluster.Shoot) {
		registryStatus, err := a.computeProviderStatus(ctx, registryConfig, namespace)
		if err != nil {
			return fmt.Errorf("failed to compute provider status: %w", err)
		}

		if err := a.updateProviderStatus(ctx, ex, registryStatus); err != nil {
			return fmt.Errorf("failed to update Extension status: %w", err)
		}
	}

	return nil
}

// Delete the Extension resource.
func (a *actuator) Delete(ctx context.Context, _ logr.Logger, ex *extensionsv1alpha1.Extension) error {
	if ex.Status.ProviderStatus != nil {
		registryStatus := &v1alpha1.RegistryStatus{}
		if _, _, err := a.decoder.Decode(ex.Status.ProviderStatus.Raw, nil, registryStatus); err != nil {
			return fmt.Errorf("failed to decode providerStatus of extension '%s': %w", client.ObjectKeyFromObject(ex), err)
		}

		for _, cache := range registryStatus.Caches {
			namespace := ex.GetNamespace()
			values := registryconfigurationcleaner.Values{Upstream: cache.Upstream}
			cleaner := registryconfigurationcleaner.New(a.client, namespace, values)

			if err := component.OpWait(cleaner).Deploy(ctx); err != nil {
				return fmt.Errorf("failed to deploy the registry configuration cleaner component for upstream %s: %w", cache.Upstream, err)
			}

			if err := component.OpDestroyAndWait(cleaner).Destroy(ctx); err != nil {
				return fmt.Errorf("failed to destroy the registry configuration cleaner component for upstream %s: %w", cache.Upstream, err)
			}
		}
	}

	namespace := ex.GetNamespace()
	registryCaches := registrycaches.New(a.client, namespace, registrycaches.Values{})

	if err := component.OpDestroyAndWait(registryCaches).Destroy(ctx); err != nil {
		return fmt.Errorf("failed to destroy the registry caches component: %w", err)
	}

	return nil
}

// Restore the Extension resource.
func (a *actuator) Restore(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Reconcile(ctx, log, ex)
}

// Migrate the Extension resource.
func (a *actuator) Migrate(_ context.Context, _ logr.Logger, _ *extensionsv1alpha1.Extension) error {
	return nil
}

func (a *actuator) computeProviderStatus(ctx context.Context, registryConfig *v1alpha1.RegistryConfig, namespace string) (*v1alpha1.RegistryStatus, error) {
	// get service IPs from shoot
	_, shootClient, err := util.NewClientForShoot(ctx, a.client, namespace, client.Options{}, extensionsconfig.RESTOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create shoot client: %w", err)
	}

	selector := labels.NewSelector()
	r, err := labels.NewRequirement(constants.UpstreamHostLabel, selection.Exists, nil)
	if err != nil {
		return nil, err
	}
	selector = selector.Add(*r)

	// get all registry cache services
	services := &corev1.ServiceList{}
	if err := shootClient.List(ctx, services, client.InNamespace(metav1.NamespaceSystem), client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, fmt.Errorf("failed to read services from shoot: %w", err)
	}

	if len(services.Items) != len(registryConfig.Caches) {
		return nil, fmt.Errorf("not all services for all configured caches exist")
	}

	caches := []v1alpha1.RegistryCacheStatus{}
	for _, service := range services.Items {
		caches = append(caches, v1alpha1.RegistryCacheStatus{
			Upstream: service.Labels[constants.UpstreamHostLabel],
			Endpoint: fmt.Sprintf("http://%s:%d", service.Spec.ClusterIP, constants.RegistryCachePort),
		})
	}

	return &v1alpha1.RegistryStatus{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.SchemeGroupVersion.String(),
			Kind:       "RegistryStatus",
		},
		Caches: caches,
	}, nil
}

func (a *actuator) updateProviderStatus(ctx context.Context, ex *extensionsv1alpha1.Extension, registryStatus *v1alpha1.RegistryStatus) error {
	patch := client.MergeFrom(ex.DeepCopy())
	ex.Status.ProviderStatus = &runtime.RawExtension{Object: registryStatus}
	return a.client.Status().Patch(ctx, ex, patch)
}
