### IDCS Activation Handler ###

Sample of a custom handler for user activation in IDCS. This is intended to be used in place of the default initial set password flow, to allow for fine grained control over the look and feel of the screens, and control over post-activation actions. This demonstrates how to leverage the same email tokens which are send by default by the IDCS notification service on user account creation in order to perform an initial set of a password and activation of the user.

For more details, see the associated Red Thunder [blog post](https://redthunder.blog/2018/10/24/custom-user-activation-and-password-reset-flows-in-oracle-idcs/).