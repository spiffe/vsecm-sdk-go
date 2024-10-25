![VSecM Logo](https://vsecm.com/vsecm.png)

## Contributing to VMware Secrets Manager Go SDK

We welcome contributions from the community and first want to thank you for
taking the time to contribute!

Please familiarize yourself with our [Code of Conduct](CODE_OF_CONDUCT.md) 
before contributing.

Before you start working with VMware Secrets Manager Go SDK, please read our
[Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions
to this repository must be signed as described on that page. Your signature
certifies that you wrote the patch or have the right to pass it on as an
open-source patch.

We appreciate any help, be it in the form of code, documentation, design,
or even bug reports and feature requests.

When contributing to this repository, please first discuss the change you wish
to make via an issue, email, or any other method before making a change.
This way, we can avoid misunderstandings and wasted effort.

One great way to initiate such discussions is asking a question
[SPIFFE Slack Community][slack].

[slack]: https://slack.spiffe.io/ "Join SPIFFE on Slack"

Please note that [we have a code of conduct](CODE_OF_CONDUCT.md). We expect all
contributors to adhere to it in all interactions with the project.

## Ways to contribute

We welcome many different types of contributions and not all of them need a
Pull request. Contributions may include:

* New features and proposals
* Documentation
* Bug fixes
* Issue Triage
* Answering questions and giving feedback
* Helping to onboard new contributors
* Other related activities

## Getting started

Please [read the developer guide][use-the-source] to
learn how to build, deploy, and test **VMware Secrets Manager** from the
source.

[use-the-source]: https://vsecm.com/documentation/development/use-the-source/

The developer guide also includes common errors that you might find when
building, deploying, and testing **VMware Secrets Manager**. 

Since the SDKs are used in conjunction with **VMware Secrets Manager**, it is
important for you to get familiar with the build and development process of it
too.

## Contribution Flow

This is a rough outline of what a contributor's workflow looks like:

* Make a fork of the repository within your GitHub account.
* Create a topic branch in your fork from where you want to base your work
* Make commits of logical units.
* Make sure your commit messages are with the proper format,
  quality and descriptiveness (*see below*)
* Adhere to the code standards described below.
* Push your changes to the topic branch in your fork
* Ensure all components build and function properly on a local
  Kubernetes cluster (*such as Minikube*).
* Update necessary `README.md` and other documents to reflect your changes.
* Keep pull requests as granular as possible. Reviewing large amounts of code
  can be error-prone and time-consuming for the reviewers.
* Create a pull request containing that commit.
* Engage in the discussion under the pull request and proceed accordingly.

## Pull Request Checklist

Before submitting your pull request, we advise you to use the following:

1. Check if your code changes will pass local tests
   (*i.e., `go test ./...` should exit with a `0` success status code*).
2. Ensure your commit messages are descriptive. We follow the conventions
   on [How to Write a Git Commit Message](http://chris.beams.io/posts/git-commit/).
   Be sure to include any related GitHub issue references in the commit message.
   See [GFM syntax](https://guides.github.com/features/mastering-markdown/#GitHub-flavored-markdown)
   for referencing issues and commits.
3. Check the commits and commits messages and ensure they are free from typos.

## Reporting Bugs and Creating Issues

For specifics on what to include in your report, please follow the guidelines
in the issue and pull request templates when available.

## Ask for Help

The best way to reach us with a question when contributing is to ask on:

* The original GitHub issue
* [**SPIFFE Slack Workspace**][slack-invite]

### Code Standards

In **VMware Secrets Manager** SDKs, we aim for a unified and clean codebase.

When contributing, please try to match the style of the code that you see in
the file you're working on. The file should look as if it was authored by a
single person after your changes.

For Go files, we require that you run `gofmt` before submitting your pull
request to ensure consistent formatting.

### Testing

Before submitting your pull request, make sure your changes pass all the
existing tests, and add new ones if necessary.

## Building VMware Secrets Manager for Development

To build **VMware Secrets Manager** from source code and develop locally,
[follow the contributing guidelines here][contributing].

If you are a maintainer, and you are preparing a release,
[follow the release guidelines here][release].

[contributing]: https://vsecm.com/use-the-source/
[release]: https://vsecm.com/release/
[slack-invite]: https://slack.spiffe.io/ "Join SPIFFE Slack"
