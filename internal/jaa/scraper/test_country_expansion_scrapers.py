#!/usr/bin/env python3
"""Offline parser/registry checks for the deep CH/IE/NL expansion."""

import json

from scraper.adapters.base import load_adapter
from scraper.adapters.country_common import jobposting_json_ld, relevant_title
from scraper.adapters.ireland_boards import (
    _hidden_rows, _jobsireland_detail, _jobsireland_pdf_text,
    _publicjobs_detail, _publicjobs_rows,
)


def main() -> None:
    nested = {
        "@context": "https://schema.org",
        "@type": "WebPage",
        "mainEntity": {
            "@type": "JobPosting", "title": "Applied AI Engineer",
            "description": "<p>Build production systems.</p>",
        },
    }
    parsed = jobposting_json_ld(
        '<script type="application/ld+json">' + json.dumps(nested) + "</script>"
    )
    assert parsed["title"] == "Applied AI Engineer"
    broken = '''<script type="application/ld+json">{
      "@context":"https://schema.org", "@type":"JobPosting",
      "title":"Automation Engineer", "description":"Build "quoted" workflows",
      "datePosted":"2026-07-19", "hiringOrganization":{"name":"Small Firm"}
    }</script>'''
    recovered = jobposting_json_ld(broken)
    assert recovered["title"] == "Automation Engineer"
    assert recovered["structured_data_recovered"] is True
    assert relevant_title("Machine-learning ontwikkelaar")
    assert relevant_title("ICT informatiebeveiliging specialist")
    assert not relevant_title("Cafe Assistant")
    assert not relevant_title("Security Guard - Tallaght")
    assert not relevant_title("Administrator (HR) - Foodcloud")
    assert relevant_title("Cloud Security Engineer")

    cards = '''
      <input class="totalCount" value="2">
      <div class="job-heading"><input id="JobId" value="11">
      <input id="JobTitle" value="Cloud Engineer"><input id="Location" value="Dublin">
      <input id="StartDate" value="2026-07-19"><input id="EndDate" value="2026-08-01"></div>
      <div class="job-heading"><input id="JobId" value="12">
      <input id="JobTitle" value="Chef"><input id="Location" value="Cork"></div>
    '''
    rows = _hidden_rows(cards)
    assert [row["JobId"] for row in rows] == ["11", "12"]

    detail = '''
      <main><div class="job-details"><h3>Cloud Engineer</h3><ul class="job-detail_list">
      <li><strong>Employer:</strong> Small Travel Company</li>
      <li><strong>Location:</strong> Dublin, Ireland</li>
      <li><strong>Salary:</strong> EUR 55,000</li></ul></div>
      <h3>Job Description</h3><pre ng-bind-html="Description | linky">
      Build Azure and Python automation. Required: Terraform, SQL, CI/CD and APIs.
      This is a complete vacancy description suitable for parser validation.</pre></main>
    '''
    ireland = _jobsireland_detail(detail, "https://jobsireland.test/11")
    assert ireland["title"] == "Cloud Engineer"
    assert ireland["company"] == "Small Travel Company"
    assert "Terraform" in ireland["content_text"]

    report_text = '''Small Travel Company\n#JOB-11\nDublin, Ireland
    \nNo of positions : 1\nPaid Position\n40 hours per week
    \n55000-60000 Euro Annually\n19/07/2026\n31/07/2026
    \nHow to apply\nApplication Method :\nPlease apply by email
    \nwww.jobsireland.ie | Phone: 123\nCloud Engineer\nApplication Details
    \nPermit guidance and application instructions for candidates.
    \nJob Description\nBuild Azure, Terraform, Python and CI/CD systems for a travel
    business. Sector: information and communication. Career Level: Entry Level.'''
    pdf_job = _jobsireland_pdf_text(
        report_text, rows[0], "https://jobsireland.test/11", "https://report.test/11"
    )
    assert pdf_job["title"] == "Cloud Engineer"
    assert pdf_job["company"] == "Small Travel Company"
    assert pdf_job["detail_fetch_status"] == "official_pdf_complete"
    derived = _jobsireland_pdf_text(
        report_text, {}, "https://jobsireland.test/11", "https://report.test/11"
    )
    assert derived["title"] == "Cloud Engineer"
    assert derived["location_text"] == "Dublin, Ireland"
    assert derived["application_deadline"] == "31/07/2026"

    listing = '''
      <li class="opp-container" data-oppid="6841"><div class="candidate-opp-tile"
      data-oppid="6841" data-title="Cyber Security Specialist">
      <a class="subject" href="https://public.test/opp/6841">Cyber Security Specialist</a>
      <div><span>Advertising Date:</span> 10 Jul 2026</div></div></li>
    '''
    public_rows = _publicjobs_rows(listing)
    assert public_rows[0]["id"] == "6841"
    public_detail = '''
      <div id="vac_desc"><h1>Cyber Security Specialist</h1>
      <h4>Department/Authority</h4><p>National Cyber Centre</p>
      <h4>Location</h4><p>Dublin</p><h4>Contract</h4><p>Permanent</p>
      <p>Protect national systems and coordinate incident response across agencies.</p>
      <a class="file_application_pdf" href="https://public.test/booklet.pdf">Candidate Booklet</a>
      </div></main>
    '''
    public = _publicjobs_detail(public_detail, "https://public.test/opp/6841")
    assert public["company"] == "National Cyber Centre"
    assert public["attachments"][0]["label"] == "Candidate Booklet"

    for board in (
        "itjobsch", "itboardch", "swissaijob", "jobsireland", "publicjobsie",
        "academictransfer", "werkenvoornederland", "magnetme", "undutchables",
        "graduatenl", "developerjobsch", "swissfederal",
    ):
        assert load_adapter(board).board == board
    print("test_country_expansion_scrapers: PASS")


if __name__ == "__main__":
    main()
