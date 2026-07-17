from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import Page, sync_playwright


BASE_URL = "http://127.0.0.1:5173"
SCREENSHOTS = Path(__file__).with_name("screenshots")
VIEWPORTS = {
    "mobile": {"width": 375, "height": 667},
    "tablet": {"width": 768, "height": 1024},
    "desktop": {"width": 1280, "height": 720},
    "wide": {"width": 1920, "height": 1080},
}


def page_metrics(page: Page) -> dict[str, object]:
    return page.evaluate(
        """() => {
          const visible = (element) => {
            const rect = element.getBoundingClientRect();
            const style = getComputedStyle(element);
            return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && style.display !== 'none';
          };
          const controls = [...document.querySelectorAll('button, input, textarea, select, a[href]')]
            .filter(visible)
            .map((element) => {
              const rect = element.getBoundingClientRect();
              const labels = element.labels ? [...element.labels].map((label) => label.innerText.trim()) : [];
              const name = element.getAttribute('aria-label') || labels.join(' ') ||
                element.textContent?.trim() || element.getAttribute('placeholder') || element.getAttribute('title') || '';
              return {
                tag: element.tagName.toLowerCase(),
                name: name.slice(0, 100),
                width: Math.round(rect.width * 10) / 10,
                height: Math.round(rect.height * 10) / 10,
              };
            });
          return {
            horizontalOverflow: document.documentElement.scrollWidth > window.innerWidth,
            documentWidth: document.documentElement.scrollWidth,
            viewportWidth: window.innerWidth,
            h1Count: document.querySelectorAll('h1').length,
            headings: [...document.querySelectorAll('h1, h2, h3')].filter(visible).map((heading) => ({
              level: Number(heading.tagName.slice(1)),
              text: heading.textContent?.trim(),
            })),
            landmarks: {
              header: document.querySelectorAll('header').length,
              main: document.querySelectorAll('main').length,
              aside: document.querySelectorAll('aside').length,
            },
            controls,
            unnamedControls: controls.filter((control) => !control.name),
          };
        }"""
    )


def contrast_findings(page: Page) -> list[dict[str, object]]:
    return page.evaluate(
        """() => {
          const parse = (value) => {
            const match = value.match(/rgba?\\(([^)]+)\\)/);
            if (!match) return null;
            const parts = match[1].split(',').map(Number);
            return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
          };
          const luminance = ({r, g, b}) => {
            const channel = (value) => {
              const normalized = value / 255;
              return normalized <= 0.03928 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
            };
            return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
          };
          const background = (element) => {
            let current = element;
            while (current) {
              const color = parse(getComputedStyle(current).backgroundColor);
              if (color && color.a > 0.95) return color;
              current = current.parentElement;
            }
            return { r: 255, g: 255, b: 255, a: 1 };
          };
          return [...document.querySelectorAll('p, span, label, button, a, h1, h2, h3, li, code, q, strong, em')]
            .filter((element) => {
              const rect = element.getBoundingClientRect();
              return rect.width > 0 && rect.height > 0 && element.textContent?.trim();
            })
            .map((element) => {
              const style = getComputedStyle(element);
              const foreground = parse(style.color);
              const behind = background(element);
              if (!foreground) return null;
              const light = Math.max(luminance(foreground), luminance(behind));
              const dark = Math.min(luminance(foreground), luminance(behind));
              const ratio = (light + 0.05) / (dark + 0.05);
              const size = Number.parseFloat(style.fontSize);
              const weight = Number.parseInt(style.fontWeight, 10) || 400;
              const large = size >= 24 || (size >= 18.66 && weight >= 700);
              return {
                tag: element.tagName.toLowerCase(),
                text: element.textContent.trim().slice(0, 80),
                ratio: Math.round(ratio * 100) / 100,
                required: large ? 3 : 4.5,
              };
            })
            .filter((finding) => finding && finding.ratio < finding.required);
        }"""
    )


def focus_trace(page: Page, steps: int = 10) -> list[dict[str, object]]:
    page.locator("body").click(position={"x": 1, "y": 1})
    trace: list[dict[str, object]] = []
    for _ in range(steps):
        page.keyboard.press("Tab")
        trace.append(
            page.evaluate(
                """() => {
                  const element = document.activeElement;
                  const style = getComputedStyle(element);
                  return {
                    tag: element?.tagName?.toLowerCase(),
                    name: element?.getAttribute?.('aria-label') || element?.textContent?.trim() ||
                      element?.getAttribute?.('placeholder') || '',
                    focusVisible: element?.matches?.(':focus-visible') || false,
                    outlineStyle: style.outlineStyle,
                    outlineWidth: style.outlineWidth,
                  };
                }"""
            )
        )
    return trace


def ax_summary(page: Page) -> dict[str, object]:
    session = page.context.new_cdp_session(page)
    session.send("Accessibility.enable")
    nodes = session.send("Accessibility.getFullAXTree")["nodes"]
    interactive_roles = {"button", "checkbox", "textbox", "link"}
    interactive = []
    for node in nodes:
        role = node.get("role", {}).get("value")
        if role not in interactive_roles or node.get("ignored"):
            continue
        interactive.append({"role": role, "name": node.get("name", {}).get("value", "")})
    return {
        "interactiveCount": len(interactive),
        "unnamedInteractive": [item for item in interactive if not item["name"]],
        "roles": interactive,
    }


def main() -> int:
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    report: dict[str, object] = {"viewports": {}, "journeys": {}, "failures": []}
    failures: list[str] = report["failures"]  # type: ignore[assignment]
    all_console_errors: list[str] = []
    all_page_errors: list[str] = []
    all_requests: list[str] = []
    failed_responses: list[dict[str, object]] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        for name, viewport in VIEWPORTS.items():
            context = browser.new_context(viewport=viewport, reduced_motion="reduce")
            page = context.new_page()
            page.on(
                "console",
                lambda message: all_console_errors.append(
                    f"{message.type}: {message.text} @ {message.location}"
                )
                if message.type == "error"
                else None,
            )
            page.on("pageerror", lambda error: all_page_errors.append(str(error)))
            page.on("request", lambda request: all_requests.append(request.url))
            page.on(
                "response",
                lambda response: failed_responses.append({"status": response.status, "url": response.url})
                if response.status >= 400
                else None,
            )
            page.goto(BASE_URL, wait_until="domcontentloaded", timeout=30_000)
            page.get_by_role("heading", name="See what this document gives away.").wait_for()
            landing_metrics = page_metrics(page)
            landing_contrast = contrast_findings(page)
            landing_ax = ax_summary(page)
            focus = focus_trace(page) if name == "mobile" else []
            page.screenshot(path=SCREENSHOTS / f"qa-final-landing-{name}.png", full_page=True)

            page.get_by_role("button", name="Watch Cloak fix a document").click()
            page.get_by_role(
                "heading", name="This attacker could no longer identify the subject from this text."
            ).wait_for()
            passed_metrics = page_metrics(page)
            passed_contrast = contrast_findings(page)
            passed_text = page.locator("body").inner_text()
            page.screenshot(path=SCREENSHOTS / f"qa-honest-verdict-passed-{name}.png", full_page=True)

            page.get_by_role("button", name="Start over").click()
            page.get_by_role("heading", name="See what this document gives away.").wait_for()
            page.get_by_role("button", name="Watch Cloak refuse a document").click()
            page.get_by_role(
                "heading", name="Cloak cannot hide the subject without breaking the task."
            ).wait_for()
            refusal_metrics = page_metrics(page)
            refusal_contrast = contrast_findings(page)
            refusal_text = page.locator("body").inner_text()
            page.screenshot(path=SCREENSHOTS / f"qa-honest-verdict-refusal-{name}.png", full_page=True)

            mobile_small_targets = []
            if name == "mobile":
                mobile_small_targets = [
                    control
                    for control in landing_metrics["controls"]
                    if control["width"] < 44 or control["height"] < 44
                ]
            report["viewports"][name] = {  # type: ignore[index]
                "landing": landing_metrics,
                "passedVerdict": passed_metrics,
                "refusalVerdict": refusal_metrics,
                "contrastFailures": {
                    "landing": landing_contrast,
                    "passedVerdict": passed_contrast,
                    "refusalVerdict": refusal_contrast,
                },
                "ax": landing_ax,
                "focus": focus,
                "mobileSmallTargets": mobile_small_targets,
            }
            if (
                landing_metrics["horizontalOverflow"]
                or passed_metrics["horizontalOverflow"]
                or refusal_metrics["horizontalOverflow"]
            ):
                failures.append(f"{name}: horizontal overflow")
            if landing_metrics["h1Count"] != 1:
                failures.append(f"{name}: expected exactly one h1")
            if landing_metrics["unnamedControls"] or landing_ax["unnamedInteractive"]:
                failures.append(f"{name}: unnamed interactive control")
            if landing_contrast:
                failures.append(f"{name} landing: WCAG text contrast failures")
            if passed_contrast:
                failures.append(f"{name} passed verdict: WCAG text contrast failures")
            if refusal_contrast:
                failures.append(f"{name} refusal verdict: WCAG text contrast failures")
            if mobile_small_targets:
                failures.append("mobile: interactive targets smaller than 44x44")
            if "won the a regional" in passed_text:
                failures.append(f"{name}: recorded grammar corruption returned")
            refusal_expectations = [
                "The facts Cloak refused to remove",
                "someone holding matching external records or web data could still re-identify the subject",
                "Cloak will not fake privacy or destroy the facts your task depends on",
                "the only pediatric perfusionist at Redvale Community Hospital",
            ]
            for expectation in refusal_expectations:
                if expectation.lower() not in refusal_text.lower():
                    failures.append(f"{name}: refusal verdict missing {expectation!r}")
            context.close()

        context = browser.new_context(viewport=VIEWPORTS["desktop"], reduced_motion="reduce")
        page = context.new_page()
        journey_requests: list[str] = []
        page.on("request", lambda request: journey_requests.append(request.url))
        page.goto(BASE_URL, wait_until="domcontentloaded", timeout=30_000)
        page.get_by_role("button", name="Paste a sample document").click()
        page.get_by_role("button", name="Find identifiers").click()
        seal_button = page.get_by_role("button", name="Create private working copy")
        seal_button.wait_for()
        task_field = page.get_by_label("What do you want the AI to do? required · stays local")
        task_required = seal_button.is_disabled()
        task_field.fill("Summarize the project while preserving the award and teaching role.")
        task_enabled_seal = seal_button.is_enabled()
        page.screenshot(path=SCREENSHOTS / "qa-final-review-task-desktop.png", full_page=True)
        review_subject = page.get_by_label("Protected subject").input_value()
        seal_button.click()
        page.get_by_role("button", name="Test who GPT-5.6 can identify").wait_for()
        candidate = page.locator(".paper-copy").inner_text()
        page.screenshot(path=SCREENSHOTS / "qa-final-ready-desktop.png", full_page=True)
        report["journeys"]["prepareAndSeal"] = {  # type: ignore[index]
            "subject": review_subject,
            "taskRequired": task_required,
            "taskEnabledSeal": task_enabled_seal,
            "candidateUsesNaturalSurrogate": "[[CX_" not in candidate,
            "candidateContainsRawSubject": "Mara Voss" in candidate,
            "candidateContainsRawEmail": "mara.voss@example.com" in candidate,
        }
        if not task_required or not task_enabled_seal:
            failures.append("prepare-and-seal: local downstream task was not required")
        if "[[CX_" in candidate or "Mara Voss" in candidate or "mara.voss@example.com" in candidate:
            failures.append("prepare-and-seal: candidate privacy boundary failed")

        page.goto(BASE_URL, wait_until="domcontentloaded", timeout=30_000)
        emoji_input = "😀" * 12_001
        page.get_by_label("Sensitive document").fill(emoji_input)
        stored = page.get_by_label("Sensitive document").input_value()
        counter = page.locator("#document-character-count").inner_text()
        report["journeys"]["unicodeLimit"] = {  # type: ignore[index]
            "storedCodePoints": len(stored),
            "counter": counter,
        }
        if len(stored) != 12_000 or "12,000 / 12,000" not in counter:
            failures.append("unicode-limit: browser UI did not enforce 12,000 code points")
        context.close()
        browser.close()

    allowed_hosts = {"127.0.0.1", "localhost"}
    unexpected_requests = sorted(
        {
            url
            for url in all_requests
            if urlparse(url).scheme in {"http", "https", "ws", "wss"} and urlparse(url).hostname not in allowed_hosts
        }
    )
    report["network"] = {
        "requestCount": len(all_requests),
        "unexpectedRequests": unexpected_requests,
        "failedResponses": failed_responses,
    }
    report["consoleErrors"] = all_console_errors
    report["pageErrors"] = all_page_errors
    if unexpected_requests:
        failures.append("network: unexpected non-loopback request")
    if failed_responses:
        failures.append("network: failed HTTP response")
    if all_console_errors or all_page_errors:
        failures.append("browser: console or page error")

    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
