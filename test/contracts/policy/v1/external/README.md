# External check judge fixtures

Each file holds cases in the `aplane.policy-external-judge.v1` format: one
external check's rules, a unit's facts, an answer, and whether the check
passes for it. They freeze how a cosigner judges an answer
(`externalcheck.Judge`): exact decimal numbers, exact strings, strict types,
RFC 6901 pointers and the echo. The rules are described in
[ARCH_POLICY.md](../../../../../docs/ARCH_POLICY.md#running-the-checks).

| File | What it pins |
|---|---|
| `numbers.json` | Equal decimals written differently, and exactness past float64 |
| `ordering.json` | `lt`, `le`, `gt` and `ge` at their bounds, and on values that are not numbers |
| `missing_and_types.json` | Missing values, `null` and values of another type, for `ne` and `not_in` too; `present` and `absent` |
| `pointers.json` | Strict array indices and escaped member names |
| `strings_and_facts.json` | Exact strings, booleans, and facts compared by their own type |
| `membership.json` | `in` and `not_in` by value |
| `echo.json` | `echo_pointer` and the lookup's request ID |

A case has these fields:

- `name`: unique within its file.
- `scope`: the check's scope, `request`, `transaction` or `movement`;
  absent means `movement`. It decides which facts a rule may name.
- `require`: the check's rules, exactly as in a policy document.
- `echo_pointer`: optional, as in a policy document.
- `request_id`: the ID the lookup was sent with; absent means none.
- `facts`: the unit's facts by name, each a string as the cosigner holds
  it; a fact the unit lacks is left out.
- `answer`: the source's answer, any JSON value. It is read as written,
  so a number keeps its literal.
- `expect.result`: `pass` or `fail`. `expect.detail` is required for a
  `fail` and is text the refusal's detail must contain; a `pass` has none.

`TestJudgeFixtures` in
`internal/signerapp/externalcheck/judge_fixtures_test.go` decodes each
check through the policy decoder as the only check of a cosigner document,
reads the answer with the cosigner's answer reader (`ParseAnswer`), and
judges it with `Judge`. It also requires that the fixtures together use
every operator and operand kind, an `echo_pointer`, and both results.

These fixtures are a contract. A changed expectation is a changed rule
semantic: what an operator's source can rely on and what a policy author
wrote against. Change one only together with the rules it describes.
