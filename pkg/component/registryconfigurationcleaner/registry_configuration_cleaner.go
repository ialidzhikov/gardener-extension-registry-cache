// Copyright (c) 2023 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package registryconfigurationcleaner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gardener/gardener/pkg/component"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	managedResourceNamePrefix = "extension-registry-configuration-cleaner"
)

type Values struct {
	Upstream string
}

func New(
	client client.Client,
	namespace string,
	values Values,
) component.DeployWaiter {
	return &registryConfigurationCleaner{
		client:    client,
		namespace: namespace,
		values:    values,
	}
}

type registryConfigurationCleaner struct {
	client    client.Client
	namespace string
	values    Values
}

func (r *registryConfigurationCleaner) Deploy(ctx context.Context) error {
	data, err := r.computeResourcesData(r.values.Upstream)
	if err != nil {
		return err
	}

	escapedUpstreamName := strings.Replace(strings.Split(r.values.Upstream, ":")[0], ".", "-", -1)
	managedResourceName := managedResourceNamePrefix + escapedUpstreamName
	//managedresources.CreateForShoot(ctx, c, namespace, managedResourceName, managedresources.LabelValueGardener, false, registry.SerializedObjects())

	origin := "registry-cache"

	return managedresources.CreateForShoot(ctx, r.client, r.namespace, managedResourceName, origin, false, data)
}

func (r *registryConfigurationCleaner) Destroy(ctx context.Context) error {
	escapedUpstreamName := strings.Replace(strings.Split(r.values.Upstream, ":")[0], ".", "-", -1)
	managedResourceName := managedResourceNamePrefix + escapedUpstreamName

	return managedresources.Delete(ctx, r.client, r.namespace, managedResourceName, false)
}

// TODO: check if we need to increase the timeout

// TimeoutWaitForManagedResource is the timeout used while waiting for the ManagedResources to become healthy
// or deleted.
var TimeoutWaitForManagedResource = 2 * time.Minute

// Wait implements component.DeployWaiter.
func (r *registryConfigurationCleaner) Wait(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	escapedUpstreamName := strings.Replace(strings.Split(r.values.Upstream, ":")[0], ".", "-", -1)
	managedResourceName := managedResourceNamePrefix + escapedUpstreamName

	return managedresources.WaitUntilHealthy(timeoutCtx, r.client, r.namespace, managedResourceName)
}

// WaitCleanup implements component.DeployWaiter.
func (r *registryConfigurationCleaner) WaitCleanup(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	escapedUpstreamName := strings.Replace(strings.Split(r.values.Upstream, ":")[0], ".", "-", -1)
	managedResourceName := managedResourceNamePrefix + escapedUpstreamName

	return managedresources.WaitUntilDeleted(timeoutCtx, r.client, r.namespace, managedResourceName)
}

func (r *registryConfigurationCleaner) computeResourcesData(upstream string) (map[string][]byte, error) {
	mountPropagationHostToContainer := corev1.MountPropagationHostToContainer

	escapedUpstreamName := strings.Replace(strings.Split(upstream, ":")[0], ".", "-", -1)

	_ = &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("registry-%s-configuration-cleaner", escapedUpstreamName),
			Namespace: "kube-system",
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					// TODO: use better labels
					Labels: map[string]string{
						"app.kubernetes.io/name": fmt.Sprintf("registry-%s-configuration-cleaner", escapedUpstreamName),
					},
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:            "registry-configuration-cleaner",
							Image:           "eu.gcr.io/gardener-project/3rd/alpine:3.15.8",
							ImagePullPolicy: corev1.PullIfNotPresent,
							SecurityContext: &corev1.SecurityContext{
								Privileged: pointer.Bool(true),
							},
							Command: []string{
								"sh",
								"-c",
								`
if [[ -f /host/etc/systemd/system/configure-registry-docker-io.service ]]; then
  chroot /host /bin/bash -c 'systemctl disable configure-registry-docker-io.service; systemctl stop configure-registry-docker-io.service; rm -f /etc/systemd/system/configure-registry-docker-io.service'
fi
					
if [[ -d /host/etc/containerd/certs.d/docker.io ]]; then
  rm -rf /host/etc/containerd/certs.d/docker.io
fi`,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:             "host-root-volume",
									MountPath:        "/host",
									ReadOnly:         true,
									MountPropagation: &mountPropagationHostToContainer,
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "pause",
							Image:           "registry.k8s.io/pause:3.7",
							ImagePullPolicy: corev1.PullIfNotPresent,
						},
					},
					HostPID: true,
					Volumes: []corev1.Volume{
						{
							Name: "host-root-volume",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/",
								},
							},
						},
					},
				},
			},
		},
	}

	return nil, nil
}
