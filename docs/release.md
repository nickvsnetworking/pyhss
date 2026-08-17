# How to make a PyHSS release

* Create a pull request with a release commit containing the following:
  * `lib/version.py`: update `pyhss_version`
  * `CHANGELOG.md`:
    * Replace `## [Unreleased]` with the new version number and date in this
      format: `## [1.0.1] - 2024-01-23`
    * Add a new line at the bottom of the document linking to the future tag.
  * `debian/changelog`:
    * Run `gbp dch --ignore-branch` to update it with a list of commits since
      the file was last changed.
    * Adjust the first line in `debian/changelog`:
      * Adjust the version number.
      * Change `UNRELEASED` to `unstable`.

* After the PR is merged:
  * `git tag NEWRELEASEVERSION`
  * `git push origin NEWRELEASEVERSION`

* Add a new `## [Unreleased]` section in `CHANGELOG.md`
