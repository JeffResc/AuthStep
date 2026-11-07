## Summary

<!-- Brief description of the changes -->

## Checklist

- [ ] Tests pass (`go test -race ./...`, `node --test internal/web/jstest/*.test.mjs`)
- [ ] Linter passes (`golangci-lint run --timeout=5m ./...`)
- [ ] Helm chart tests pass if the chart changed (`helm unittest charts/authstep`)
- [ ] Documentation updated if applicable
