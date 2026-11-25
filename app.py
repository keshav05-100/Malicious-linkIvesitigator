from urllib.parse import urlparse

from flask import Flask, render_template, request, abort

from analyzer import analyze_url


app = Flask(__name__)

# The form only ever needs a URL; refuse oversized request bodies.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


@app.before_request
def reject_cross_site_posts():
    """
    This app makes outbound requests on the user's behalf. Without this check,
    any web page the user visits could silently POST a URL to
    http://127.0.0.1:5000 and make it fetch arbitrary targets (CSRF).
    """
    if request.method == "POST":
        origin = request.headers.get("Origin")

        if origin and urlparse(origin).netloc != request.host:
            abort(403)


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.route("/", methods=["GET", "POST"])
def index():

    result = None
    error = None
    submitted_url = ""

    if request.method == "POST":

        submitted_url = request.form.get("url", "").strip()

        if not submitted_url:
            error = "Please enter a URL."

        else:
            try:
                result = analyze_url(submitted_url)
            except Exception:
                # Never show a raw 500 page / stack trace for a bad target.
                app.logger.exception("Analysis failed")
                result = {
                    "success": False,
                    "error": "Analysis failed unexpectedly. Please try another URL.",
                }

            if not result["success"]:
                error = result["error"]
                result = None

    return render_template(
        "index.html",
        result=result,
        error=error,
        submitted_url=submitted_url,
    )


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
