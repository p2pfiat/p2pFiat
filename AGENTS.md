# Working agreement for AI agents

Two AI agents develop this repository side by side, like two developers: **Claude** (Claude Code) and **Gemini** (Antigravity / Gemini CLI). The repository owner is the human maintainer and has the final say. Pull requests let both agents work at the same time without getting in each other's way. A review by the other agent is optional: ask for one only when you are unsure.

## Who works where

Each agent has its own clone. Never edit, commit in, or switch branches in the other agent's folder.

| Agent | Folder | Branch prefix |
|---|---|---|
| Claude | `C:\personal\claude\p2pfiat\<repo>` | `claude/` |
| Gemini | `C:\personal\antigravity\p2pfiat\<repo>` | `gemini/` |

## Rules

1. **Never push to `main`.** `main` is protected; all changes arrive by pull request.
2. **One task, one branch, one PR.** Start from a fresh `main` (`git switch main && git pull`), then `git switch -c claude/<short-topic>` or `gemini/<short-topic>`. Keep PRs small enough to review in one sitting.
3. **Mark who wrote a commit.** End each commit message with a trailer for the agent: `Co-Authored-By: Claude <noreply@anthropic.com>` or `Co-Authored-By: Gemini <noreply@google.com>`.
4. **Open the PR yourself** with `gh pr create`, titled `[Claude] …` or `[Gemini] …`, and fill in the template: what changed, why, how you tested it (commands and results), and the risks. Post PR text with `--body-file <file>` (PowerShell eats backticks in inline text).
5. **Test before you hand over.** The author runs the tests below for what they changed and puts the results in the PR. That, not a review, is the normal bar for a merge.
6. **Ask for a review only when you are unsure.** For example: a change you could not test, a design choice with several reasonable options, or a risky change to keys, signatures, scripts, amounts, fees or timelocks that the tests do not fully cover. Then add the label `review-wanted` and say in the PR what the reviewer should look at. A reviewer posts `gh pr review <n> --comment --body-file <file>` and sets `approved-by-claude` / `approved-by-gemini` or `changes-requested-by-claude` / `changes-requested-by-gemini`. Both agents share one GitHub account, so GitHub's Approve button is not available.
7. **Stay out of each other's way.** Before starting, check the open PRs (`gh pr list`) so you do not change the same files as the other agent at the same time. If you must, say so in your PR. Rebase or merge `main` into your branch when it moves.
8. **Only the maintainer merges.** Neither agent merges, closes the other's PR, or force-pushes to the other agent's branch. After the merge, the author deletes the branch.
9. **No secrets.** Never read, print or commit private keys, seeds, `priv_key.txt`, `.env` files or tokens.

## Tests

- **p2pFiat, offer book and wallet logic:** `cd mvp && node --test "test/*.test.mjs"` (quoted, so Node expands the glob in any shell)
- **p2pFiat, web app:** `cd mvp/web && npm ci && npm run build`
- **p2pFiat, watchtower:** `cd watchtower && cargo test`
- **p2pFiat, experiments:** see each `experiments/<n>/README.md` (they need the local regtest stack).

If a test cannot run (for example because the regtest stack is down), say so in the PR instead of skipping it silently.
