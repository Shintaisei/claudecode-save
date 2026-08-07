# formal_14 abort decision

The gpt-5.4-mini Stage-3 sentinel completed with a correct two-step output, but
its guard trace accepted `reg.exe|registry_write|observed_registry_target`.
`observed_registry_target` is still a generic placeholder, not a concrete
registry path or value. This is a validator vocabulary gap rather than a model
quality result.

The completed runs are preserved, but formal_14 must not be resumed or
formally aggregated. The correction is versioned as atomic guard v12 and uses
the create-only `normal8_three_model_three_stage_formal_15` result root.
