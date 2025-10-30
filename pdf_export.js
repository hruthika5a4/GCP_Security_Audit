import puppeteer from "puppeteer";

(async () => {
  const browser = await puppeteer.launch({
    headless: true,
    args: ["--no-sandbox"]
  });

  const page = await browser.newPage();
  await page.goto("http://localhost:8080", { waitUntil: "networkidle0" });

  await page.pdf({
    path: "gcp_audit_report.pdf",
    format: "A4",
    landscape: true,
    printBackground: true,
  });

  await browser.close();
})();
