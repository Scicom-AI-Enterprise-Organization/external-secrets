/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"

// HuaweiCloudProvider configures a store to sync secrets from Huawei Cloud Stack
// Cloud Secret Management Service (CSMS).
type HuaweiCloudProvider struct {
	// Endpoint is the full CSMS base URL.
	// Example: https://csms.cn-north-4.myhuaweicloud.com
	// +kubebuilder:validation:MinLength=1
	Endpoint string `json:"endpoint"`

	// ProjectID is the HCS project ID.
	// +kubebuilder:validation:MinLength=1
	ProjectID string `json:"projectID"`

	// Auth configures how the operator authenticates with CSMS.
	Auth HuaweiCloudAuth `json:"auth"`
}

// HuaweiCloudAuth holds the authentication configuration for HCS CSMS.
// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:MaxProperties=1
type HuaweiCloudAuth struct {
	// SecretRef references Kubernetes Secrets containing the AK and SK.
	// +optional
	SecretRef *HuaweiCloudAuthSecretRef `json:"secretRef,omitempty"`
}

// HuaweiCloudAuthSecretRef references Kubernetes Secrets holding the
// Access Key (AK) and Secret Key (SK) for HCS AK/SK authentication.
type HuaweiCloudAuthSecretRef struct {
	// AccessKeySecretRef points to the Kubernetes Secret key holding the Access Key (AK).
	// +optional
	AccessKeySecretRef esmeta.SecretKeySelector `json:"accessKeySecretRef,omitempty"`

	// SecretKeySecretRef points to the Kubernetes Secret key holding the Secret Key (SK).
	// +optional
	SecretKeySecretRef esmeta.SecretKeySelector `json:"secretKeySecretRef,omitempty"`
}
