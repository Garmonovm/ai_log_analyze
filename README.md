# AI incident log analyzer

Sends a production log to an AI model and writes a short, structured incident report (`report.md`).

## Run
Requires Python 3.8+
#### You need an API token to run the script.

```bash
cd ai_log_analyze
export API_TOKEN=<token>
python3 analyze.py                 # analyzes it_task_log.log
```

```bash
python3 analyze.py other.log -o out.md
python3 analyze.py --json   # creates report.md and report.json 
```

- Takes about 30 seconds. Log size limit: 150 KB. Usage limit: 20 requests per day, 1 per second.

## How it works
`analyze.py` -> APIGW `https://incident-ai.trussardiops.click/analyze` -> AI model -> report.

## AI usage
- **Tool:** GitHub Copilot with Claude Sonnet. Used for planning, implementation and testing.
The infrastructure was created with Terraform:
- API Gateway REST API with a custom domain (Route53 + ACM certificate)
- Lambda authorizer: Bearer token stored in AWS Secrets Manager, valid for 48 hours
- Usage plan: 20 requests/day, 1 request/second; request size limit 150 KB
- Lambda analyzer calling Amazon Bedrock (Claude Sonnet)

## Adjustments made during development
1. **Too long JSON:** the first version returned a large JSON that was hard to read and hard to understand. It was restructured into a Markdown report with only the critical information.
2. **Poorly formatted Markdown:** all details (service, evidence) were on one line. Restructured into sections, a services table and bullet lists, and shortened the text.
3. **Too technical language:** the summary and the failure reasons had too many technical parameters. The text was rewritten in simpler language, so the report is easier to understand, and it still keeps all technical information.
4. **Missing data check:** the report said that some transactions could have failed and not been written to the database. A separate section was added for such cases, because they can be critical and need verification.
5. **API Gateway timeout:** the maximum API Gateway integration timeout is 29 s, which is not enough for Sonnet. The AWS Service Quota was increased to 60 s.
