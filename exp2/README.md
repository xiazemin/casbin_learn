casebin 使用

exp1
	a := xormadapter.NewAdapter("mysql", "root:@tcp(127.0.0.1:3306)/goblog?charset=utf8", true)
    e := casbin.NewEnforcer("./exp1/rbac_models.conf", a)
    if ok := e.AddPolicy("admin", "/api/v1/hello", "GET"); !ok {
    if ok := e.Enforce(sub, obj, act); ok {

exp2
	m := model.Model{}

    m.LoadModelFromText(modelText)

    e := casbin.NewEnforcer(m)

    pass := e.Enforce(p, g, "In", env)



1，type Model map[string]AssertionMap
type AssertionMap map[string]*Assertion
// Assertion represents an expression in a section of the model.
// For example: r = sub, obj, act
type Assertion struct {
	Key    string
	Value  string
	Tokens []string
	Policy [][]string
	RM     rbac.RoleManager
}

// RoleManager provides interface to define the operations for managing roles.
type RoleManager interface {
	// Clear clears all stored data and resets the role manager to the initial state.
	Clear() error
	// AddLink adds the inheritance link between two roles. role: name1 and role: name2.
	// domain is a prefix to the roles (can be used for other purposes).
	AddLink(name1 string, name2 string, domain ...string) error
	// DeleteLink deletes the inheritance link between two roles. role: name1 and role: name2.
	// domain is a prefix to the roles (can be used for other purposes).
	DeleteLink(name1 string, name2 string, domain ...string) error
	// HasLink determines whether a link exists between two roles. role: name1 inherits role: name2.
	// domain is a prefix to the roles (can be used for other purposes).
	HasLink(name1 string, name2 string, domain ...string) (bool, error)
	// GetRoles gets the roles that a user inherits.
	// domain is a prefix to the roles (can be used for other purposes).
	GetRoles(name string, domain ...string) ([]string, error)
	// GetUsers gets the users that inherits a role.
	// domain is a prefix to the users (can be used for other purposes).
	GetUsers(name string, domain ...string) ([]string, error)
	// PrintRoles prints all the roles to log.
	PrintRoles() error
}

2，func (model Model) LoadModelFromText(text string) {
	cfg, err := config.NewConfigFromText(text)
	if err != nil {
		panic(err)
	}

	loadSection(model, cfg, "r")
	loadSection(model, cfg, "p")
	loadSection(model, cfg, "e")
	loadSection(model, cfg, "m")

	loadSection(model, cfg, "g")
}

// Config represents an implementation of the ConfigInterface
type Config struct {
	// map is not safe.
	sync.RWMutex
	// Section:key=value
	data map[string]map[string]string
}

// NewConfig create an empty configuration representation from file.
func NewConfig(confName string) (ConfigInterface, error) {
	c := &Config{
		data: make(map[string]map[string]string),
	}
	err := c.parse(confName)
	return c, err
}

func (c *Config) parse(fname string) (err error) {
	c.Lock()
	f, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer c.Unlock()
	defer f.Close()

	buf := bufio.NewReader(f)
	return c.parseBuffer(buf)
}

func loadAssertion(model Model, cfg config.ConfigInterface, sec string, key string) bool {
	value := cfg.String(sectionNameMap[sec] + "::" + key)
	return model.AddDef(sec, key, value)
}

var sectionNameMap = map[string]string{
	"r": "request_definition",
	"p": "policy_definition",
	"g": "role_definition",
	"e": "policy_effect",
	"m": "matchers",
}

// AddDef adds an assertion to the model.
func (model Model) AddDef(sec string, key string, value string) bool {
	ast := Assertion{}
	ast.Key = key
	ast.Value = value

	if ast.Value == "" {
		return false
	}

	if sec == "r" || sec == "p" {
		ast.Tokens = strings.Split(ast.Value, ", ")
		for i := range ast.Tokens {
			ast.Tokens[i] = key + "_" + ast.Tokens[i]
		}
	} else {
		ast.Value = util.RemoveComments(util.EscapeAssertion(ast.Value))
	}

	_, ok := model[sec]
	if !ok {
		model[sec] = make(AssertionMap)
	}

	model[sec][key] = &ast
	return true
}

3,
// File:
// e := casbin.NewEnforcer("path/to/basic_model.conf", "path/to/basic_policy.csv")
// MySQL DB:
// a := mysqladapter.NewDBAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/")
// e := casbin.NewEnforcer("path/to/basic_model.conf", a)
func NewEnforcer(params ...interface{}) *Enforcer {
	e := &Enforcer{}
    switch p1 := params[1].(type) {
    case string:
        e.InitWithFile(p0, p1)
    default:
        e.InitWithAdapter(p0, p1.(persist.Adapter))
    }
}

// Enforcer is the main interface for authorization enforcement and policy management.
type Enforcer struct {
	modelPath string
	model     model.Model
	fm        model.FunctionMap
	eft       effect.Effector

	adapter persist.Adapter
	watcher persist.Watcher
	rm      rbac.RoleManager

	enabled            bool
	autoSave           bool
	autoBuildRoleLinks bool
}

type FunctionMap map[string]func(args ...interface{}) (interface{}, error)

// Effector is the interface for Casbin effectors.
type Effector interface {
	// MergeEffects merges all matching results collected by the enforcer into a single decision.
	MergeEffects(expr string, effects []Effect, results []float64) (bool, error)
}



// Adapter is the interface for Casbin adapters.
type Adapter interface {
	// LoadPolicy loads all policy rules from the storage.
	LoadPolicy(model model.Model) error
	// SavePolicy saves all policy rules to the storage.
	SavePolicy(model model.Model) error

	// AddPolicy adds a policy rule to the storage.
	// This is part of the Auto-Save feature.
	AddPolicy(sec string, ptype string, rule []string) error
	// RemovePolicy removes a policy rule from the storage.
	// This is part of the Auto-Save feature.
	RemovePolicy(sec string, ptype string, rule []string) error
	// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
	// This is part of the Auto-Save feature.
	RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error
}

// Watcher is the interface for Casbin watchers.
type Watcher interface {
	// SetUpdateCallback sets the callback function that the watcher will call
	// when the policy in DB has been changed by other instances.
	// A classic callback is Enforcer.LoadPolicy().
	SetUpdateCallback(func(string)) error
	// Update calls the update callback of other instances to synchronize their policy.
	// It is usually called after changing the policy in DB, like Enforcer.SavePolicy(),
	// Enforcer.AddPolicy(), Enforcer.RemovePolicy(), etc.
	Update() error
	// Close stops and releases the watcher, the callback function will not be called any more.
	Close()
}

// RoleManager provides interface to define the operations for managing roles.
type RoleManager interface {
	// Clear clears all stored data and resets the role manager to the initial state.
	Clear() error
	// AddLink adds the inheritance link between two roles. role: name1 and role: name2.
	// domain is a prefix to the roles (can be used for other purposes).
	AddLink(name1 string, name2 string, domain ...string) error
	// DeleteLink deletes the inheritance link between two roles. role: name1 and role: name2.
	// domain is a prefix to the roles (can be used for other purposes).
	DeleteLink(name1 string, name2 string, domain ...string) error
	// HasLink determines whether a link exists between two roles. role: name1 inherits role: name2.
	// domain is a prefix to the roles (can be used for other purposes).
	HasLink(name1 string, name2 string, domain ...string) (bool, error)
	// GetRoles gets the roles that a user inherits.
	// domain is a prefix to the roles (can be used for other purposes).
	GetRoles(name string, domain ...string) ([]string, error)
	// GetUsers gets the users that inherits a role.
	// domain is a prefix to the users (can be used for other purposes).
	GetUsers(name string, domain ...string) ([]string, error)
	// PrintRoles prints all the roles to log.
	PrintRoles() error
}


4,
// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
func (e *Enforcer) Enforce(rvals ...interface{}) bool {
	if !e.enabled {
		return true
	}

	functions := make(map[string]govaluate.ExpressionFunction)
	for key, function := range e.fm {
		functions[key] = function
	}
	if _, ok := e.model["g"]; ok {
		for key, ast := range e.model["g"] {
			rm := ast.RM
			functions[key] = util.GenerateGFunction(rm)
		}
	}

	expString := e.model["m"]["m"].Value
	expression, err := govaluate.NewEvaluableExpressionWithFunctions(expString, functions)
	if err != nil {
		panic(err)
	}

	rTokens := make(map[string]int, len(e.model["r"]["r"].Tokens))
	for i, token := range e.model["r"]["r"].Tokens {
		rTokens[token] = i
	}
	pTokens := make(map[string]int, len(e.model["p"]["p"].Tokens))
	for i, token := range e.model["p"]["p"].Tokens {
		pTokens[token] = i
	}

	parameters := enforceParameters{
		rTokens: rTokens,
		rVals:   rvals,

		pTokens: pTokens,
	}

	var policyEffects []effect.Effect
	var matcherResults []float64
	if policyLen := len(e.model["p"]["p"].Policy); policyLen != 0 {
		policyEffects = make([]effect.Effect, policyLen)
		matcherResults = make([]float64, policyLen)
		if len(e.model["r"]["r"].Tokens) != len(rvals) {
			panic(
				fmt.Sprintf(
					"Invalid Request Definition size: expected %d got %d rvals: %v",
					len(e.model["r"]["r"].Tokens),
					len(rvals),
					rvals))
		}
		for i, pvals := range e.model["p"]["p"].Policy {
			// log.LogPrint("Policy Rule: ", pvals)
			if len(e.model["p"]["p"].Tokens) != len(pvals) {
				panic(
					fmt.Sprintf(
						"Invalid Policy Rule size: expected %d got %d pvals: %v",
						len(e.model["p"]["p"].Tokens),
						len(pvals),
						pvals))
			}

			parameters.pVals = pvals

			result, err := expression.Eval(parameters)
			// log.LogPrint("Result: ", result)

			if err != nil {
				policyEffects[i] = effect.Indeterminate
				panic(err)
			}

			switch result := result.(type) {
			case bool:
				if !result {
					policyEffects[i] = effect.Indeterminate
					continue
				}
			case float64:
				if result == 0 {
					policyEffects[i] = effect.Indeterminate
					continue
				} else {
					matcherResults[i] = result
				}
			default:
				panic(errors.New("matcher result should be bool, int or float"))
			}

			if j, ok := parameters.pTokens["p_eft"]; ok {
				eft := parameters.pVals[j]
				if eft == "allow" {
					policyEffects[i] = effect.Allow
				} else if eft == "deny" {
					policyEffects[i] = effect.Deny
				} else {
					policyEffects[i] = effect.Indeterminate
				}
			} else {
				policyEffects[i] = effect.Allow
			}

			if e.model["e"]["e"].Value == "priority(p_eft) || deny" {
				break
			}

		}
	} else {
		policyEffects = make([]effect.Effect, 1)
		matcherResults = make([]float64, 1)

		parameters.pVals = make([]string, len(parameters.pTokens))

		result, err := expression.Eval(parameters)
		// log.LogPrint("Result: ", result)

		if err != nil {
			policyEffects[0] = effect.Indeterminate
			panic(err)
		}

		if result.(bool) {
			policyEffects[0] = effect.Allow
		} else {
			policyEffects[0] = effect.Indeterminate
		}
	}

	// log.LogPrint("Rule Results: ", policyEffects)

	result, err := e.eft.MergeEffects(e.model["e"]["e"].Value, policyEffects, matcherResults)
	if err != nil {
		panic(err)
	}

	// Log request.
	if log.GetLogger().IsEnabled() {
		reqStr := "Request: "
		for i, rval := range rvals {
			if i != len(rvals)-1 {
				reqStr += fmt.Sprintf("%v, ", rval)
			} else {
				reqStr += fmt.Sprintf("%v", rval)
			}
		}
		reqStr += fmt.Sprintf(" ---> %t", result)
		log.LogPrint(reqStr)
	}

	return result
}


// GenerateGFunction is the factory method of the g(_, _) function.
func GenerateGFunction(rm rbac.RoleManager) func(args ...interface{}) (interface{}, error) {
	return func(args ...interface{}) (interface{}, error) {
		name1 := args[0].(string)
		name2 := args[1].(string)

		if rm == nil {
			return name1 == name2, nil
		} else if len(args) == 2 {
			res, _ := rm.HasLink(name1, name2)
			return res, nil
		} else {
			domain := args[2].(string)
			res, _ := rm.HasLink(name1, name2, domain)
			return res, nil
		}
	}
}

#规则引擎
"github.com/Knetic/govaluate"

expression, err := govaluate.NewEvaluableExpressionWithFunctions(expString, functions)

    
type EvaluableExpression struct {

	/*
		Represents the query format used to output dates. Typically only used when creating SQL or Mongo queries from an expression.
		Defaults to the complete ISO8601 format, including nanoseconds.
	*/
	QueryDateFormat string

	/*
		Whether or not to safely check types when evaluating.
		If true, this library will return error messages when invalid types are used.
		If false, the library will panic when operators encounter types they can't use.

		This is exclusively for users who need to squeeze every ounce of speed out of the library as they can,
		and you should only set this to false if you know exactly what you're doing.
	*/
	ChecksTypes bool

	tokens           []ExpressionToken
	evaluationStages *evaluationStage
	inputExpression  string
}

func parseTokens(expression string, functions map[string]ExpressionFunction) ([]ExpressionToken, error) {

	var ret []ExpressionToken
	var token ExpressionToken
	var stream *lexerStream
	var state lexerState
	var err error
	var found bool

	stream = newLexerStream(expression)
	state = validLexerStates[0]

	for stream.canRead() {

		token, err, found = readToken(stream, state, functions)

		if err != nil {
			return ret, err
		}

		if !found {
			break
		}

		state, err = getLexerStateForToken(token.Kind)
		if err != nil {
			return ret, err
		}

		// append this valid token
		ret = append(ret, token)
	}

	err = checkBalance(ret)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

https://zhuanlan.zhihu.com/p/122561534

https://www.jianshu.com/p/77c0e9e9f153


result, err := expression.Eval(parameters)

result, err := e.eft.MergeEffects(e.model["e"]["e"].Value, policyEffects, matcherResults)


tree
.
|____model_b_test.go
|____rbac_api_with_domains_test.go
|____rbac_api_with_domains_synced.go
|____rbac
| |____role_manager.go
| |____default-role-manager
| | |____role_manager.go
| | |____role_manager_test.go
|____go.mod
|____filter_test.go
|____enforcer_test.go
|____internal_api.go
|____model_test.go
|____management_api_test.go
|____LICENSE
|____casbin-logo.png
|____util
| |____builtin_operators.go
| |____builtin_operators_test.go
| |____util_test.go
| |____util.go
|____config
| |____testdata
| | |____testini.ini
| |____config.go
| |____config_test.go
|____watcher_test.go
|____enforcer_cached.go
|____enforcer_synced.go
|____enforcer.go
|____effect
| |____effector.go
| |____default_effector.go
|____go.sum
|____rbac_api_test.go
|____enforcer_safe.go
|____rbac_api.go
|____README.md
|____rbac_api_with_domains.go
|____.gitignore
|____enforcer_cached_b_test.go
|____examples
| |____rbac_policy.csv
| |____rbac_with_hierarchy_policy.csv
| |____keymatch2_policy.csv
| |____basic_without_resources_policy.csv
| |____basic_with_root_model.conf
| |____ipmatch_model.conf
| |____basic_inverse_policy.csv
| |____rbac_with_domains_model.conf
| |____priority_indeterminate_policy.csv
| |____keymatch_custom_model.conf
| |____rbac_with_resource_roles_policy.csv
| |____rbac_with_deny_policy.csv
| |____abac_model.conf
| |____basic_without_users_model.conf
| |____rbac_with_hierarchy_with_domains_policy.csv
| |____keymatch_policy.csv
| |____priority_model.conf
| |____rbac_with_pattern_model.conf
| |____rbac_with_not_deny_model.conf
| |____basic_model.conf
| |____keymatch2_model.conf
| |____basic_without_resources_model.conf
| |____rbac_model_in_multi_line.conf
| |____rbac_model.conf
| |____ipmatch_policy.csv
| |____rbac_with_resource_roles_model.conf
| |____rbac_with_deny_model.conf
| |____rbac_with_domains_policy.csv
| |____error
| | |____error_policy.csv
| | |____error_model.conf
| |____rbac_with_pattern_policy.csv
| |____priority_policy.csv
| |____basic_policy.csv
| |____basic_without_users_policy.csv
| |____rbac_model_matcher_using_in_op.conf
| |____keymatch_model.conf
|____management_api.go
|____.github
| |____FUNDING.yml
|____model
| |____model_test.go
| |____assertion.go
| |____policy.go
| |____model.go
| |____function.go
|____rbac_api_synced.go
|____enforcer_synced_test.go
|____log
| |____logger.go
| |____log_util.go
| |____default_logger.go
| |____log_util_test.go
|____error_test.go
|____errors
| |____rbac_errors.go
|____enforcer_cached_test.go
|____enforcer_synced_safe.go
|____persist
| |____file-adapter
| | |____adapter.go
| | |____adapter_mock.go
| | |____adapter_filtered.go
| |____adapter.go
| |____persist_test.go
| |____adapter_filtered.go
| |____watcher.go
|____.travis.yml