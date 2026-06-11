# Research direction

## Purpose

This experiment evaluates whether an LLM-driven investigation workflow can reconstruct benign security behavior chains from alert and telemetry context, rather than only summarize isolated alert rows.

The core research question is:

> How accurately can an LLM reconstruct a causal behavior chain when the starting information is weakened from explicit alert input to process/time-only context?

## Motivation

Security alert triage often requires connecting multiple log events into a coherent behavior story: parent-child process execution, command-line intent, file/network side effects, registry semantics, and temporal order. The experiment treats this as a behavior reconstruction task.

## Hypotheses

1. Richer starting information improves reconstruction.
2. Stronger models recover more behavior from telemetry-only conditions.
3. Reconstruction difficulty depends on chain structure:
   - explicit command/process chains are easier,
   - multi-step tool chains increase order and overclaim errors,
   - app/registry semantic chains require interpretation beyond event matching.

## Contribution target

The work aims to contribute an evaluation design for normal/benign behavior reconstruction in security logs, using:

- chain-level gold behavior definitions,
- staged input conditions,
- item-level and sequence-level scoring,
- scenario-structure analysis.
