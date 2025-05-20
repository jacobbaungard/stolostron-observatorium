package v1

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"reflect"

	"github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/authorization"
	"github.com/observatorium/api/httperr"

	// "k8s.io/klog"
	userv1 "github.com/openshift/api/user/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// ACLConfig holds the  access control configuration  needed to  perform an action
// e.g. "get" permission on the  "managedclusters" resource is needed to "view" a managedcluster on the ACM Hub.
// The configuration includes ApiGroup, Resource type but not Version as rules in K8s ClusterRole
// do not include/specify version.
type ACLConfig struct {
	// groupRes is the API Group and Resource information
	groupRes schema.GroupResource
	// verb is the action on the Resource
	verb string
}

// MetricsACLConfig is an instance of ACLConfig and holds configuration for accessing observability
// metrics gathered from ManagedClusters
var mcoaroleACLConfig = ACLConfig{
	groupRes: schema.GroupResource{
		Group:    "observability.open-cluster-management.io",
		Resource: "observabilityaddonroles",
	},
}

var mcoaroleGVR = schema.GroupVersionResource{
	Group:    "observability.open-cluster-management.io",
	Version:  "v1",
	Resource: "observabilityaddonroles",
}

// WithEnforceTenancyOnQuery returns a middleware that ensures that every query has a tenant label enforced.
func WithEnforceTenancyOnQuery(tenantLabel string, paramName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Adapted from
		// https://github.com/prometheus-community/prom-label-proxy/blob/952266db4e0b8ab66b690501e532eaef33300596/injectproxy/routes.go.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID, ok := authentication.GetTenantID(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant ID", http.StatusInternalServerError)
				return
			}

			tenantMatcher := &labels.Matcher{
				Name:  tenantLabel,
				Type:  labels.MatchEqual,
				Value: tenantID,
			}
			e := injectproxy.NewEnforcer(false, tenantMatcher)
			// If we cannot enforce, don't continue.
			if ok := enforceRequestQueryLabels(e, paramName, w, r); !ok {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WithEnforceAuthorizationLabels returns a middleware that ensures every query
// has a set of labels returned by the OPA authorizer enforced.
func WithEnforceAuthorizationLabels() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, ok := authorization.GetData(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding authorization label matcher", http.StatusInternalServerError)

				return
			}

			// Early pass to the next if no authz
			// label enforcement configured.
			if data == "" {
				next.ServeHTTP(w, r)

				return
			}

			var lm []*labels.Matcher
			if err := json.Unmarshal([]byte(data), &lm); err != nil {
				httperr.PrometheusAPIError(w, "error parsing authorization label matcher", http.StatusInternalServerError)

				return
			}

			e := injectproxy.NewEnforcer(false, lm...)
			// If we cannot enforce, don't continue.
			if ok := enforceRequestQueryLabels(e, "query", w, r); !ok {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// returns:
// []labels.Matcher: matchers to apply, nil if user has acess to everything
// bool: true if user doesn't have access to anything
func getLBACLabelMatchers(userToken string) ([]labels.Matcher, bool) {
	var matchers []labels.Matcher
	noAccess := true

	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		fmt.Printf("error creating dynamic client: %v\n", err)
		panic(err)
	}

	user := GetUserName(userToken, config.Host+"/apis/user.openshift.io/v1/users/~")
	fmt.Println("Checking access for user: ", user)

	mcoaroles, err := dynamicClient.Resource(mcoaroleGVR).Namespace("open-cluster-management-observability").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		fmt.Printf("error getting roles: %v\n", err)
		panic(err)
	}
	fmt.Printf("There are %d mcoaroles in the cluster\n", len(mcoaroles.Items))

	// assume full access if there are no roles
	if len(mcoaroles.Items) == 0 {
		fmt.Printf("There are no mcoaroles in the cluster, granting full access")
		return nil, false
	}

	// Now get the login for the actual user
	kubeClient, err := getKubeClientForUser(userToken)
	if err != nil {
		return nil, true
	}

	// check if user has access to all mcoaroles in the namespace, if so we assume admin and apply no matchers
	a := kubeClient.AuthorizationV1().SelfSubjectAccessReviews()
	sar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "open-cluster-management-observability",
				Verb:      "get",
				Resource:  "observabilityaddonroles",
				Name:      "*",
				Group:    "observability.open-cluster-management.io",
				Version:  "v1",
			},
		},
	}

	response, err := a.Create(context.TODO(), sar, metav1.CreateOptions{})
	if err != nil {
		panic(err)
	}

	fmt.Printf("get all observabilityaddonroles is %v \n", response.Status.Allowed)
	// user can access all mcoa roles and therefore we grant full access
	if response.Status.Allowed {
		return nil, false
	}


	// Now loop through all the roles to find the label matchers
	for _, mcoarole := range mcoaroles.Items {
		var name string
		if str, ok := mcoarole.Object["metadata"].(map[string]interface{})["name"].(string); ok {
			name = str
		} else {
			panic("Name is mcoarole is not a string")
		}

		// TODO: skip non-metric actions
		// if str, ok := mcoarole.Object["spec"].(map[string]interface{})["actions"].(string); ok {
		// 	name = str
		// } else {
		// 	panic("Name is mcoarole is not a string")
		// }

		// auth := kubeClient.AuthorizationV1().SelfSubjectAccessReviews()
		sar := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "open-cluster-management-observability",
					Verb:      "get",
					Resource:  "observabilityaddonroles",
					Name:      name,
					Group:    "observability.open-cluster-management.io",
					Version:  "v1",
				},
			},
		}

		response, err := a.Create(context.TODO(), sar, metav1.CreateOptions{})
		if err != nil {
			panic(err)
		}

		fmt.Printf(
			"Name: %s, allowed: %v\n",
			name,
			response.Status.Allowed,
		)
		fmt.Printf("%v\n", mcoarole.Object["spec"].(map[string]interface{})["scopes"])
		fmt.Println(reflect.TypeOf(mcoarole.Object["spec"].(map[string]interface{})["scopes"]))
		if response.Status.Allowed {
			// Get the scope
			scopes := mcoarole.Object["spec"].(map[string]interface{})["scopes"].([]interface {})
			for _, scope := range scopes {
				scopeStr := scope.(string)
				fmt.Printf("Scope: %s\n", scopeStr)
				// parser.ParseMetricSelector(scopeStr)
				matcher, err2 := parser.ParseMetricSelector("{"+scopeStr+"}")
				if err2 != nil {
					fmt.Errorf(err2.Error())
					fmt.Printf("error???\n")
				 	panic(err2.Error())
				 }
				for _, match := range matcher {
					fmt.Printf("Add matcher\n")
					noAccess = false
					matchers = append(matchers, *match)
				}
			}
		}
	}

	fmt.Printf("Return matchers\n")
	return matchers, noAccess
}

func WithLBAC(enableLBAC bool, paramName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			//  1) Get list of MCOA roles using the pods service account
			//  1.5) If none found, assume full access
			//  2) Using the forwarded users token, do access review on all MCOA roles
			//  3) Apply any labelmatchers found from MCOA roles which the forwarded user can access
			if enableLBAC {
				token := r.Header.Get("X-Forwarded-Access-Token")
				matchers, noAccess := getLBACLabelMatchers(token)

				// return nothing if user does not have access
				if (noAccess) {
					return 
				}
				for _, match := range matchers {
					e := injectproxy.NewEnforcer(false, &match)	
					fmt.Printf("Applying matcher: %s\n", match.String())
					if ok := enforceRequestQueryLabels(e, paramName, w, r); !ok {
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func enforceRequestQueryLabels(e *injectproxy.Enforcer, paramName string, w http.ResponseWriter, r *http.Request) bool {
	// The `query` can come in the URL query string and/or the POST body.
	// For this reason, we need to try to enforcing in both places.
	// Note: a POST request may include some values in the URL query string
	// and others in the body. If both locations include a `query`, then
	// enforce in both places.
	q, foundQuery, err := enforceQueryValues(e, paramName, r.URL.Query())
	if err != nil {
		httperr.PrometheusAPIError(w, fmt.Sprintf("could not enforce labels: %v", err), http.StatusBadRequest)

		return false
	}

	r.URL.RawQuery = q

	var foundForm bool
	// Enforce the query in the POST body if needed.
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			// We're returning server error here because we cannot ensure this is a bad request.
			httperr.PrometheusAPIError(w, fmt.Sprintf("could not parse form: %v", err), http.StatusInternalServerError)

			return false
		}

		q, foundForm, err = enforceQueryValues(e, paramName, r.PostForm)
		if err != nil {
			httperr.PrometheusAPIError(w, fmt.Sprintf("could not enforce labels: %v", err), http.StatusBadRequest)

			return false
		}
		// We are replacing request body, close previous one (ParseForm ensures it is read fully and not nil).
		_ = r.Body.Close()
		r.Body = io.NopCloser(strings.NewReader(q))
		r.ContentLength = int64(len(q))
		r.Header.Set("Content-Length", strconv.Itoa(len(q)))
	}

	// If no query was found, return early.
	if !foundQuery && !foundForm {
		httperr.PrometheusAPIError(w, "no query found", http.StatusBadRequest)

		return false
	}

	return true
}

// Adapted from
// https://github.com/prometheus-community/prom-label-proxy/blob/952266db4e0b8ab66b690501e532eaef33300596/injectproxy/routes.go.
func enforceQueryValues(e *injectproxy.Enforcer, paramName string, requestParams url.Values) (values string, foundQuery bool, err error) {
	if len(requestParams[paramName]) == 0 {
		// This is a dirty hack to force the introduction of a match[] param to add tenancy
		// enforcement even when the param isn't present. This is needed because match[] is
		// optional for label names and values, yet we have to add it to avoid leaks.
		// Would love to find a cleaner way to do it.
		enforcedMatchers, err := e.EnforceMatchers([]*labels.Matcher{})
		if err != nil {
			return "", false, fmt.Errorf("enforce matchers error: %w", err)
		}
		requestParams.Set(paramName, matchersToString(enforcedMatchers...))
		return requestParams.Encode(), true, nil
	}

	matchers := requestParams[paramName]
	for i, rawMatcher := range matchers {
		expr, err := parser.ParseExpr(rawMatcher)
		if err != nil {
			return "", true, fmt.Errorf("parse expr error: %w", err)
		}
		fmt.Printf("Prior to enforcement: %s\n", expr.String())
		if err := e.EnforceNode(expr); err != nil {
			return "", true, fmt.Errorf("enforce node error: %w", err)
		}
		fmt.Printf("Post enforcement: %s\n", expr.String())
		matchers[i] = expr.String()
	}
	return requestParams.Encode(), true, nil
}

func matchersToString(ms ...*labels.Matcher) string {
	el := make([]string, 0, len(ms))
	for _, m := range ms {
		el = append(el, m.String())
	}
	return fmt.Sprintf("{%v}", strings.Join(el, ","))
}

// getKubeClientForUser returns the k8s client to use to connect to the cluster.
// - userToken is the user's OAuth bearer token.  It will be used along with the k8sConfig,
// set on the AccessReviewer, to create a new k8s client. If k8sConfig is not available,
// then the configured k8s client is returned.
func getKubeClientForUser(userToken string) (kubernetes.Interface, error) {
	// if a valid userToken
	if userToken != "" {
		config, err := rest.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}

		// tokenfile takes precedence over token,
		// set tokenfile to empty to ensure token is used
		config.BearerTokenFile = ""
		config.BearerToken = userToken
		// create the clientset
		kclient, err := kubernetes.NewForConfig(config)
		if err != nil {
			return nil, err
		}

		return kclient, nil
	} else {
		return nil, fmt.Errorf(
			"failed to get a client to connect to the kubernetes cluster:" +
				"When KubeConfig is provided, a valid userToken must be set on all access review calls")
	}
}

// GetResourceAccess returns all configured ACLs for a given resource type.
// It returns a map of resource names and ACLs for that resource. for a given resource,
// if no  ACLs are configured, an empty list is returned for it in the results.
//
// - resourcenames are the names of the resources for which ACLs are and returned,
// if no resource names are passed, ACLs for all allowed resources of the given type are returned.
//
// - namespace is used for namespace-scoped resources, for cluster-scoped resources it should be left empty.
// If not specified, it defaults to the value "default" for namespace-scoped resources.
func GetResourceAccess(
	kclient kubernetes.Interface, gr schema.GroupResource, resourcenames []string, namespace string,
) (map[string][]string, error) {
	fmt.Printf(
		"GetResourceAccess for GroupResource: %s, resourcenames: %v, namespace: %s\n", gr, resourcenames, namespace)

	// make a SelfSubjectRulesReview to get all resource rules.
	resourceRules, err := makeSubjectRulesReviewForUser(kclient, namespace)
	if err != nil {
		return nil, err
	}

	resourceAccessResults := make(map[string][]string)
	// search through all the resource rules
	fmt.Printf("Looking for rules containing: group: %v, resource: %v\n", gr.Group, gr.Resource)
	for _, rule := range resourceRules {
		// each resource rule contains { []ApiGroup, []Resources, []ResourceNames, []Verbs}
		// e.g: {[metrics/nsred1 metrics/nsred2] [cluster.open-cluster-management.io]
		// [managedclusters] [devcluster1 devcluster2]}
		// filter the rules by the given ApiGroup(or *) and Resource(or *))
		fmt.Printf("Evaluation rule. APIGroup: %v, Resource: %v\n", rule.APIGroups, rule.Resources)
		ruleMatchesAPIGroup := (slices.Contains(rule.APIGroups, gr.Group) || slices.Contains(rule.APIGroups, "*"))
		ruleMatchesResource := (slices.Contains(rule.Resources, gr.Resource) || slices.Contains(rule.Resources, "*"))

		if !(ruleMatchesAPIGroup && ruleMatchesResource) {
			continue
		}

		fmt.Printf("Found Rule that matches the given GroupResource %v\n", rule)

		// if a set of resource names are included in the rule, then add the acls only for those resources names
		if len(rule.ResourceNames) != 0 {
			for _, ruleResourceName := range rule.ResourceNames {
				// if given resourcenames is empty or contains the resourcename in the rule,
				//  apply rule to that resourcename
				if len(resourcenames) == 0 || slices.Contains(resourcenames, ruleResourceName) {
					// add verbs that are not already in the list
					resourceAccessResults[ruleResourceName] = addUniqueItems(
						resourceAccessResults[ruleResourceName], rule.Verbs...)
				}
			}
		} else {
			// if no resource names are set on the rule, it means acls in it apply to all resources of this type
			if len(resourcenames) != 0 {
				// if given resourcenames is nonempty,
				// add acls to  each of the resourcename as the rule appplies to all  of the type
				for _, rname := range resourcenames {
					// add verbs that are not already in the list
					resourceAccessResults[rname] = addUniqueItems(resourceAccessResults[rname], rule.Verbs...)
				}
			} else {
				// if given resourcenames is empty,  add acls under the "*" entry as rule applied to all
				resourceAccessResults["*"] = addUniqueItems(resourceAccessResults["*"], rule.Verbs...)
			}
		}
	}

	// the above only adds entries for the resourcenames that have some acls associated with it
	// so add empty entries for any resourcenames that are missing in the result list
	if len(resourcenames) != 0 {
		for _, rname := range resourcenames {
			if _, ok := resourceAccessResults[rname]; !ok {
				resourceAccessResults[rname] = []string{}
			}
		}
	}

	fmt.Printf("Resource access results %v\n", resourceAccessResults)

	return resourceAccessResults, nil
}

// addUniqueItems a convenience method for building a slice with unique entries
// specified items are added to the given slice of items if not already in it
func addUniqueItems(itemlist []string, itemsToAdd ...string) []string {
	fmt.Printf("Adding items %v to list %v\n", itemsToAdd, itemlist)

	// iterate through each of the items in  itemsToAdd list
	// and add item only if it doesnt already exist in the itemlist
	resultList := itemlist
	for _, item := range itemsToAdd {
		// check if itemList  contains the item before appending
		if !slices.Contains(resultList, item) {
			resultList = append(resultList, item)
		}
	}

	fmt.Printf("Result List: %v \n", resultList)

	return resultList
}

// makeSubjectRulesReviewForUser is a helper function that makes a SelfSubjectRulesReview call
// on the k8s cluster. If the call is successful then it returns a slice of all ResourceRules
// configured for the user.
//
// - namespace is the namespace to set  in the selfsubjectaccessreview call, if not specified
// it defaults to an invalid namespace to limit the response to cluster scoped resources.
func makeSubjectRulesReviewForUser(
	kclient kubernetes.Interface, namespace string,
) ([]authorizationv1.ResourceRule, error) {
	fmt.Printf("Make Subject Access Rules Review for Namespace %s\n", namespace)

	// selfsubjectaccessreview needs to be  for a specific namespace
	// It returns ResourceRules for all allowed namespace-scoped resources in the given namespace
	// +  all allowed cluster-scoped resources
	// When the user's bearer token is used to make the call instead of  user impersonation,
	// the user's usergroup info is already taken into account when returning the acls
	// if the call is successful then this function returns a list of resourcerules

	if namespace == "" {
		// This is a workaround for SelfSubjectRulesReview errantly accepting RoleBindings on the default namespace
		// for cluster scoped access. Only ClusterRoleBindings actually affect access.
		namespace = "$ Invalid $"
	}

	sarr := &authorizationv1.SelfSubjectRulesReview{
		Spec: authorizationv1.SelfSubjectRulesReviewSpec{
			Namespace: namespace,
		},
	}

	response, err := kclient.AuthorizationV1().SelfSubjectRulesReviews().Create(
		context.TODO(), sarr, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	sarrStatus := response.Status

	// Log the evaluation error but don't block since partial results is better than completely failing.
	if sarrStatus.EvaluationError != "" {
		fmt.Printf(
			"Encountered a SelfSubjectRulesReviews error in namespace %s: %v\n", namespace, sarrStatus.EvaluationError,
		)
	}

	fmt.Printf("Resources Rule : %v\n", sarrStatus.ResourceRules)

	return sarrStatus.ResourceRules, nil
}

func GetUserName(token string, url string) string {
	resp, err := sendHTTPRequest(url, "GET", token)
	if err != nil {
		fmt.Errorf("failed to send http request: %v", err)
		return ""
	}

	user := userv1.User{}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			fmt.Errorf("failed to close response body: %v", err)
		}
	}()

	err = json.NewDecoder(resp.Body).Decode(&user)
	if err != nil {
		fmt.Errorf("failed to decode response json body: %v", err)
		return ""
	}

	return user.Name
}

func sendHTTPRequest(url string, verb string, token string) (*http.Response, error) {
	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	req, err := http.NewRequest(verb, url, nil)
	if err != nil {
		fmt.Errorf("failed to new http request: %v", err)
		return nil, err
	}

	if len(token) == 0 {
		transport := &http.Transport{}
		defaultClient := &http.Client{Transport: transport}
		return defaultClient.Do(req)
	}

	if !strings.HasPrefix(token, "Bearer ") {
		token = "Bearer " + token
	}
	req.Header.Set("Authorization", token)
	caCert, err := os.ReadFile(filepath.Clean(caPath))
	if err != nil {
		fmt.Errorf("failed to load root ca cert file")
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		},
		MaxIdleConns:    100,
		IdleConnTimeout: 60 * time.Second,
	}

	client := http.Client{Transport: tr}
	return client.Do(req)
}
