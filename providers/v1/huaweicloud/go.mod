module github.com/external-secrets/external-secrets/providers/v1/huaweicloud

go 1.26.1

require (
	github.com/external-secrets/external-secrets/apis v0.0.0
	github.com/external-secrets/external-secrets/runtime v0.0.0
	k8s.io/api v0.35.0
	k8s.io/apimachinery v0.35.0
	sigs.k8s.io/controller-runtime v0.23.1
)

replace (
	github.com/external-secrets/external-secrets/apis => ../../../apis
	github.com/external-secrets/external-secrets/runtime => ../../../runtime
)
