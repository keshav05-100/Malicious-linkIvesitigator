import sys
from analyzer import analyze_url


def print_line():
    print("-" * 65)


def print_result(result):

    print()
    print_line()
    print("             PHISHING URL DETECTOR")
    print_line()

    print(f"URL     : {result['normalized_url']}")
    print(f"Domain  : {result['domain']}")

    if result["ip"]:
        print(f"IP      : {result['ip']}")
    else:
        print("IP      : Not resolved")

    print(f"HTTPS   : {'YES' if result['https'] else 'NO'}")
    print(f"Length  : {result['url_length']} characters")

    if result["http_status"]:
        print(f"HTTP    : {result['http_status']}")

    if result["final_url"] != result["normalized_url"]:
        print(f"Final   : {result['final_url']}")

    print()
    print(f"RISK SCORE : {result['score']}/100")
    print(f"VERDICT    : {result['verdict']}")

    print()
    print("FINDINGS")
    print_line()

    if not result["findings"]:
        print("No major suspicious indicators detected.")

    else:

        for number, finding in enumerate(
            result["findings"],
            start=1
        ):

            print(
                f"{number}. "
                f"[{finding['severity'].upper()}] "
                f"{finding['reason']}"
            )

    print_line()
    print()


def main():

    # URL passed directly:
    #
    # python main.py https://example.com
    #
    if len(sys.argv) > 1:

        url = sys.argv[1]

    else:

        try:
            url = input("Enter URL: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            sys.exit(1)

    if not url:
        print("No URL provided.")
        sys.exit(1)

    print("\nAnalyzing URL...\n")

    try:
        result = analyze_url(url)
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(1)

    if not result["success"]:
        print(f"ERROR: {result['error']}")
        sys.exit(1)

    print_result(result)


if __name__ == "__main__":
    main()
