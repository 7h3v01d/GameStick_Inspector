# Full-Image Consistency Analysis

GameStick Inspector 0.5.0-alpha8 adds a read-only comparison layer for complete SD-card acquisitions.

## Purpose

The feature answers a narrower question than filesystem probing:

> When multiple complete images are read from nominally the same card, exactly where do the captured bytes agree or disagree?

It does **not** decide that any one acquisition is "correct" merely because it was captured first or came from a preferred reader.

## Classification

At each refined sector:

- `UNANIMOUS` — every image contains exactly the same bytes.
- `MAJORITY` — with at least three inputs, one exact byte variant is present in strictly more than half of the images.
- `SPLIT` — no strict majority exists. For two-image comparisons, every disagreement is therefore `SPLIT`.

The analyzer first compares 4 MiB chunks. Only disagreeing chunks are refined to 512-byte sectors, which keeps identical-image comparison efficient while still localizing differences.

## Evidence output

The JSON report records:

- complete SHA-256 of each input image;
- equal input size;
- unanimous / majority / split chunk counts;
- unanimous / majority / split sector counts;
- strict-majority consensus coverage for 3+ images;
- bounded coalesced disagreement ranges;
- per-image count of sectors that deviate from a strict majority.

Raw payload bytes are not exported.

## Safety boundary

- Inputs are opened read-only.
- No GameStick device is written.
- No input image is modified.
- The report writer refuses to target an input image.
- No consensus image is created in alpha8.
- Cancellation writes no partial report.

A future consensus-materialization phase must have a separate explicit policy for ambiguous sectors rather than silently selecting bytes.
