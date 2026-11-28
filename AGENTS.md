# Working agreement for AI agents

Two AI agents develop this repository side by side, like two developers: **Claude** (Claude Code) and **Gemini** (Antigravity / Gemini CLI). The repository owner is the human maintainer and has the final say. Every change goes through a pull request that the other agent reviews.

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
4. **Open the PR yourself** with `gh pr create`, titled `[Claude] …` or `[Gemini] …`, and fill in the template: what changed, why, how you tested it (commands and results), and the risks.
5. **Ask the other agent to review.** Both agents use the same GitHub account, so GitHub's "Approve" button is not available. Reviews are posted as review comments, and the verdict is a label:
   - `gh pr review <n> --comment --body "..."` for the review itself (inline remarks are welcome);
   - then exactly one label with your name: `approved-by-claude` / `approved-by-gemini`, or `changes-requested-by-claude` / `changes-requested-by-gemini`.
6. **A review means running the code.** Check out the branch in your own folder (`gh pr checkout <n>`), run the tests below, and read the whole diff. Say what you ran. Look hardest at anything that touches keys, signatures, scripts, amounts, fees or timelocks.
7. **The author fixes, the reviewer re-checks.** Push fixes to the same branch and reply to each comment. When fixed, ask for a re-review; the reviewer swaps their `changes-requested-by-…` label for `approved-by-…`.
8. **Only the maintainer merges.** Neither agent merges, closes the other's PR, or force-pushes to the other agent's branch. After the merge, the author deletes the branch.
9. **No secrets.** Never read, print or commit private keys, seeds, `priv_key.txt`, `.env` files or tokens.

## Tests

- **p2pFiat, offer book and wallet logic:** `cd mvp && node --test "test/*.test.mjs"` (quoted, so Node expands the glob in any shell)
- **p2pFiat, web app:** `cd mvp/web && npm ci && npm run build`
- **p2pFiat, watchtower:** `cd watchtower && cargo test`
- **p2pFiat, experiments:** see each `experiments/<n>/README.md` (they need the local regtest stack).

If a test cannot run (for example because the regtest stack is down), say so in the PR instead of skipping it silently.
