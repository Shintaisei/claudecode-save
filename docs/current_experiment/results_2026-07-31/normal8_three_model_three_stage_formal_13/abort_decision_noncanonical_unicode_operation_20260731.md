# formal_13 abort decision

formal_13 was stopped during the gpt-5.5 Stage-3 sentinel. The model emitted
`reg.exe|実行時行動|未確認対象`; the operation normalized to an empty ASCII
token and bypassed the v10 missing-component guard.

This is an architecture/validator defect, not a model-quality result. The
completed gpt-4.1-mini and gpt-5.4-mini gate runs and the partial gpt-5.5 trace
are preserved, but formal_13 must not be resumed or formally aggregated.
The correction is versioned as atomic guard v11 and uses a create-only
`normal8_three_model_three_stage_formal_14` result root.
