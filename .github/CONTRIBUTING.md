# Contributing

Use the existing libcosmic widgets and Fluent messages. Keep privileged operations in the helper.
Use `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` before submitting a change. Network behavior needs an isolated integration test.

Use short Conventional Commit subjects, such as `fix: preserve the selected network interface`.
Keep each commit focused and explain behavior changes in the pull request.
