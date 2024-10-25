![VSecM Logo](https://vsecm.com/vsecm.png)

## Welcome

Thank you for your interest in contributing to **VMware Secrets Manager** 
Go SDK 🤘.

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

Also make sure you read, understand and accept
[The Developer Certificate of Origin Contribution Guide](CONTRIBUTING_DCO.md)
as it is a requirement to contribute to this project and contains more details
about the contribution process.

## No Dependency on the Parent Project

A little copying is better than a little dependency.

While contributing code to this repo, make sure that there is no dependency
on `https://github.com/vmware-tanzu/secrets-manager`. If needed, explicitly copy
entities over. The reason for this is to avoid circular dependencies and also
keep the SDKs self-sustained and isolated as a unit.

Note that, the same is not true in the other direction since certain **VSecM**
components leverage the SDKs to implement their functionalities.

## How To Run Tests

Before merging your changes, make sure all tests pass.

Turn test the SDK locally, run `go test ./...` on the project root.
