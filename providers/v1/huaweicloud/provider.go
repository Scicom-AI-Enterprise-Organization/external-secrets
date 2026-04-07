package huaweicloud

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/runtime/esutils"
)

// Compile-time interface check.
var _ esv1.Provider = &Provider{}

const (
	errInvalidStore     = "huaweicloud: invalid store: %w"
	errMissingEndpoint  = "huaweicloud: spec.provider.huaweicloud.endpoint is required"
	errMissingProjectID = "huaweicloud: spec.provider.huaweicloud.projectID is required"
	errMissingSecretRef = "huaweicloud: spec.provider.huaweicloud.auth.secretRef is required"
	errFetchCredential  = "huaweicloud: fetch credential %q from secret %q: %w"
)

// Provider is the Huawei Cloud Stack CSMS provider.
type Provider struct{}

// Capabilities returns ReadOnly since PushSecret is not implemented.
func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadOnly
}

// NewClient builds a SecretsClient from the provided SecretStore.
func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube kclient.Client, namespace string) (esv1.SecretsClient, error) {
	spec := store.GetSpec()
	if spec == nil || spec.Provider == nil || spec.Provider.HuaweiCloud == nil {
		return nil, fmt.Errorf(errInvalidStore, fmt.Errorf("missing huaweicloud provider spec"))
	}
	hc := spec.Provider.HuaweiCloud

	if hc.Endpoint == "" {
		return nil, fmt.Errorf(errMissingEndpoint)
	}
	if hc.ProjectID == "" {
		return nil, fmt.Errorf(errMissingProjectID)
	}
	if hc.Auth.SecretRef == nil {
		return nil, fmt.Errorf(errMissingSecretRef)
	}

	ak, err := fetchSecretKey(ctx, kube, namespace, store, hc.Auth.SecretRef.AccessKeySecretRef)
	if err != nil {
		return nil, fmt.Errorf(errFetchCredential, "accessKey", hc.Auth.SecretRef.AccessKeySecretRef.Name, err)
	}
	sk, err := fetchSecretKey(ctx, kube, namespace, store, hc.Auth.SecretRef.SecretKeySecretRef)
	if err != nil {
		return nil, fmt.Errorf(errFetchCredential, "secretKey", hc.Auth.SecretRef.SecretKeySecretRef.Name, err)
	}

	return &csmsClient{
		endpoint:  hc.Endpoint,
		projectID: hc.ProjectID,
		ak:        ak,
		sk:        sk,
		http: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // HCS uses self-signed certificates
			},
		},
	}, nil
}

// ValidateStore checks that the store has all required fields.
func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	spec := store.GetSpec()
	if spec == nil || spec.Provider == nil || spec.Provider.HuaweiCloud == nil {
		return nil, fmt.Errorf("missing huaweicloud provider spec")
	}
	hc := spec.Provider.HuaweiCloud

	if hc.Endpoint == "" {
		return nil, fmt.Errorf(errMissingEndpoint)
	}
	if hc.ProjectID == "" {
		return nil, fmt.Errorf(errMissingProjectID)
	}
	if hc.Auth.SecretRef == nil {
		return nil, fmt.Errorf(errMissingSecretRef)
	}
	if err := esutils.ValidateReferentSecretSelector(store, hc.Auth.SecretRef.AccessKeySecretRef); err != nil {
		return nil, fmt.Errorf("invalid auth.secretRef.accessKeySecretRef: %w", err)
	}
	if err := esutils.ValidateReferentSecretSelector(store, hc.Auth.SecretRef.SecretKeySecretRef); err != nil {
		return nil, fmt.Errorf("invalid auth.secretRef.secretKeySecretRef: %w", err)
	}
	return nil, nil
}

func fetchSecretKey(ctx context.Context, kube kclient.Client, defaultNamespace string, store esv1.GenericStore, ref esmeta.SecretKeySelector) (string, error) {
	ns := ref.Namespace
	if ns == nil || *ns == "" {
		storeNs := store.GetNamespace()
		ns = &storeNs
		if *ns == "" {
			ns = &defaultNamespace
		}
	}

	secret := &corev1.Secret{}
	if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: *ns}, secret); err != nil {
		return "", err
	}
	val, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %q", ref.Key, ref.Name)
	}
	return string(val), nil
}

// NewProvider creates a new Provider instance.
func NewProvider() esv1.Provider {
	return &Provider{}
}

// ProviderSpec returns the provider specification for registration.
func ProviderSpec() *esv1.SecretStoreProvider {
	return &esv1.SecretStoreProvider{
		HuaweiCloud: &esv1.HuaweiCloudProvider{},
	}
}

// MaintenanceStatus returns the maintenance status of the provider.
func MaintenanceStatus() esv1.MaintenanceStatus {
	return esv1.MaintenanceStatusMaintained
}
