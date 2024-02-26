module github.com/openshift/oauth-apiserver

go 1.19

require (
	github.com/MakeNowJust/heredoc v1.0.0
	github.com/google/btree v1.0.1
	github.com/google/gofuzz v1.1.0
	github.com/google/uuid v1.3.0
	github.com/jteeuwen/go-bindata v3.0.8-0.20151023091102-a0ff2567cfb7+incompatible
	github.com/openshift/api v0.0.0-20220525145417-ee5b62754c68
	github.com/openshift/apiserver-library-go v0.0.0-20220617080758-f441877bb41d
	github.com/openshift/build-machinery-go v0.0.0-20211213093930-7e33a7eb4ce3
	github.com/openshift/client-go v0.0.0-20220525160904-9e1acff93e4a
	github.com/openshift/library-go v0.0.0-20220622115547-84d884f4c9f6
	github.com/spf13/cobra v1.4.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.8.0
	k8s.io/api v0.25.15
	k8s.io/apiextensions-apiserver v0.25.15
	k8s.io/apimachinery v0.25.15
	k8s.io/apiserver v0.25.15
	k8s.io/client-go v0.25.15
	k8s.io/code-generator v0.25.15
	k8s.io/component-base v0.25.15
	k8s.io/klog/v2 v2.70.1
	k8s.io/kube-aggregator v0.25.15
	k8s.io/kube-openapi v0.0.0-20221012153701-172d655c2280
	k8s.io/kubernetes v1.25.15
	k8s.io/utils v0.0.0-20220728103510-ee6ede2d64ed
)

require (
	github.com/NYTimes/gziphandler v1.1.1 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/antlr/antlr4/runtime/Go/antlr v0.0.0-20220418222510-f25a4f6275ed // indirect
	github.com/asaskevich/govalidator v0.0.0-20190424111038-f61b66f89f4a // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd/v22 v22.3.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/emicklei/go-restful/v3 v3.8.0 // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/felixge/httpsnoop v1.0.1 // indirect
	github.com/form3tech-oss/jwt-go v3.2.3+incompatible // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/cel-go v0.12.6 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.16.0 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/profile v1.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.12.1 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/soheilhy/cmux v0.1.5 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/tmc/grpc-websocket-proxy v0.0.0-20201229170055-e5319fda7802 // indirect
	github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	go.etcd.io/etcd/api/v3 v3.5.4 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.4 // indirect
	go.etcd.io/etcd/client/v2 v2.305.4 // indirect
	go.etcd.io/etcd/client/v3 v3.5.4 // indirect
	go.etcd.io/etcd/pkg/v3 v3.5.4 // indirect
	go.etcd.io/etcd/raft/v3 v3.5.4 // indirect
	go.etcd.io/etcd/server/v3 v3.5.4 // indirect
	go.opentelemetry.io/contrib v0.20.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.20.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.20.0 // indirect
	go.opentelemetry.io/otel v0.20.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp v0.20.0 // indirect
	go.opentelemetry.io/otel/metric v0.20.0 // indirect
	go.opentelemetry.io/otel/sdk v0.20.0 // indirect
	go.opentelemetry.io/otel/sdk/export/metric v0.20.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v0.20.0 // indirect
	go.opentelemetry.io/otel/trace v0.20.0 // indirect
	go.opentelemetry.io/proto/otlp v0.7.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.19.0 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/oauth2 v0.0.0-20220411215720-9780585627b5 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/term v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8 // indirect
	golang.org/x/tools v0.6.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220502173005-c8bf987b8c21 // indirect
	google.golang.org/grpc v1.47.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/gengo v0.0.0-20211129171323-c02415ce4185 // indirect
	sigs.k8s.io/apiserver-network-proxy/konnectivity-client v0.0.37 // indirect
	sigs.k8s.io/json v0.0.0-20220713155537-f223a00ba0e2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.2.0 // indirect
)

replace (
	k8s.io/api => k8s.io/api v0.25.15
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.25.15
	k8s.io/apimachinery => k8s.io/apimachinery v0.25.15
	k8s.io/apiserver => github.com/openshift/kubernetes-apiserver v0.0.0-20231102175240-aa483e45e76b // points to openshift-apiserver-4.12-kubernetes-1.25.15
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.25.15
	k8s.io/client-go => k8s.io/client-go v0.25.15
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.25.15
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.25.15
	k8s.io/code-generator => k8s.io/code-generator v0.25.15
	k8s.io/component-base => k8s.io/component-base v0.25.15
	k8s.io/component-helpers => k8s.io/component-helpers v0.25.15
	k8s.io/controller-manager => k8s.io/controller-manager v0.25.15
	k8s.io/cri-api => k8s.io/cri-api v0.25.15
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.25.15
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.25.15
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.25.15
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20220602162414-ca8f27ec61da
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.25.15
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.25.15
	k8s.io/kubectl => k8s.io/kubectl v0.25.15
	k8s.io/kubelet => k8s.io/kubelet v0.25.15
	k8s.io/kubernetes => github.com/openshift/kubernetes v0.0.0-20231102175127-23e4a06e6b2d
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.25.15
	k8s.io/metrics => k8s.io/metrics v0.25.15
	k8s.io/mount-utils => k8s.io/mount-utils v0.25.15
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.25.15
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.25.15
)
