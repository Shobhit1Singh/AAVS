import os
import json
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv("C:/AAVS/.env")


def generate_security_report(scan_results):

    print("\n[1] ENTERED AI FUNCTION")

    api_key = os.getenv("OPENROUTER_API_KEY")

    print("\n[2] API KEY CHECK")
    print("done" if api_key else "NO KEY")

    if not api_key:
        return "OPENROUTER_API_KEY missing"

    client = OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1"
    )

    print("\n[3] CLIENT CREATED")

    findings_json = json.dumps(
        scan_results,
        indent=2
    )

    prompt = f"""
You are an expert API penetration tester and application security analyst.

Analyze the following API vulnerability scan findings and generate a professional technical security assessment report.

SCAN FINDINGS:
{findings_json}

Instructions:

1. Only report REAL vulnerabilities present in the findings.
2. Do NOT invent vulnerabilities that are not detected.
3. Group similar vulnerabilities together.
4. Prioritize critical security risks first.
5. Keep explanations concise, technical, and actionable.
6. Focus heavily on remediation guidance developers can immediately apply.
7. Mention affected endpoints clearly.
8. If findings are informational only, explicitly state that no exploitable vulnerability was confirmed.
9. Avoid generic security advice unless directly relevant.
10.Give solutions in seperate column titled solution that can be implemented and will be crucial in solving the vulnerabilities of the API.
For EACH vulnerability include:

- Vulnerability Name
- Severity
- Affected Endpoint(s)
- Technical Description
- Security Impact
- Exploit Scenario
- Root Cause
- OWASP API Security Top 10 Mapping
- Remediation Steps
- Secure Code / Architecture Recommendation
- Priority (P1/P2/P3/P4)

After all findings include:

# Overall Risk Summary
- Total vulnerabilities by severity
- Most critical issue
- Recommended immediate actions
-Tell solutions that must be implemented to solve the vulnerabilities of the API
Return STRICTLY valid markdown.

Do not wrap output inside triple backticks.
"""

    print("\n[4] PROMPT BUILT")
    print("done")
    # print("\nPROMPT SIZE:")
    # print(len(prompt))

    try:

        print("\n[5] SENDING TO OPENROUTER")

        response = client.chat.completions.create(
            model="deepseek/deepseek-chat-v3-0324",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            max_tokens=800,
            timeout=30
        )

        # print("\n[6] RESPONSE RECEIVED")

        # print("\n[6.1] FULL RESPONSE OBJECT\n")
        # print(response)

        if not response.choices:

            return (
                "No choices returned from model"
            )

        choice = response.choices[0]

        if not choice.message:

            return (
                "No message returned from model"
            )

        ai_output = choice.message.content

        if not ai_output:

            return (
                "Empty AI output returned"
            )

        print("\n[7] AI OUTPUT RECEIVED\n")

        print(ai_output)

        cleaned = (
            ai_output
            .replace("```markdown", "")
            .replace("```", "")
            .strip()
        )

        print("\n[8] CLEANED OUTPUT READY\n")

        return cleaned

    except Exception as e:

        print("\n[ERROR INSIDE AI FUNCTION]")

        print(str(e))

        return f"AI ERROR: {str(e)}"