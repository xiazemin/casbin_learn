https://casbin.org/editor/


http://127.0.0.1:9000/api/v1/get

Casbin的工作原理
在 Casbin 中, 访问控制模型被抽象为基于 **PERM **(Policy, Effect, Request, Matcher) [策略，效果，请求，匹配器]的一个文件。

Policy：定义权限的规则
Effect：定义组合了多个Policy之后的结果
Request：访问请求
Matcher：判断Request是否满足Policy
首先会定义一堆Policy，然后通过Matcher来判断Request和Policy是否匹配，然后通过Effect来判断匹配结果是Allow还是Deny。

https://os.51cto.com/art/202104/655234.htm?pc


Model CONF 至少应包含四个部分: [request_definition], [policy_definition], [policy_effect], [matchers]。
如果 model 使用 RBAC, 还需要添加[role_definition]部分。
Model CONF 文件可以包含注释。注释以 # 开头， # 会注释该行剩余部分。


request_definition：用于request的定义，它明确了e.Enforce(...)函数中参数的定义，sub, obj, act 表示经典三元组: 访问实体 (Subject)，访问资源 (Object) 和访问方法 (Action)。
policy_definition：用于policy的定义，每条规则通常以形如p的policy type开头，比如p,joker,data1,read就是一条joker具有data1读权限的规则。
role_definition：是RBAC角色继承关系的定义。g 是一个 RBAC系统，_, _表示角色继承关系的前项和后项，即前项继承后项角色的权限。
policy_effect：是对policy生效范围的定义，它对request的决策结果进行统一的决策，比如e = some(where (p.eft == allow))就表示如果存在任意一个决策结果为allow的匹配规则，则最终决策结果为allow。p.eft 表示策略规则的决策结果，可以为allow 或者deny，当不指定规则的决策结果时,取默认值allow 。
matchers：定义了策略匹配者。匹配者是一组表达式，它定义了如何根据请求来匹配策略规则

https://www.cnblogs.com/studyzy/p/11380736.html

https://gitee.com/coolops/casbin_test.git

https://blog.csdn.net/lk2684753/article/details/99680892

https://www.kancloud.cn/oldlei/casbin/1289454