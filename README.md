# Password Strength Analyzer

A Python tool that evaluates the strength of user-entered passwords based on multiple criteria.

## Features
- Checks password **length**, **complexity**, and **uniqueness**
- Detects common/weak passwords
- Checks if password appeared in real **data breaches** (via HaveIBeenPwned API)
- Suggests **stronger password alternatives**
- Password **generator** built-in

## How to Run

```bash
pip install requests
python password_analyzer.py
```

## Scoring Criteria
| Check | Max Score |
|-------|-----------|
| Length | 3 |
| Complexity (uppercase, lowercase, digits, special chars) | 4 |
| Uniqueness (no patterns/common passwords) | 2 |
| Not in breach database | 2 |
| **Total** | **11** |

## Strength Levels
- **80%+** → Strong 💪
- **60–79%** → Moderate ⚠️
- **40–59%** → Weak ❌
- **Below 40%** → Very Weak 🚨

## Tech Used
- Python 3
- `requests` library
- HaveIBeenPwned API (k-anonymity model — password never sent directly)
