/**
 * A small subset of permissions available for jobs with <a href="https://wiki.jenkins.io/display/JENKINS/Matrix-based+security">matrix-based security</a>.
 * Using an enum here avoids typos.
 * Furthermore the small subset ensures that permissions are not used negiently.
 * <p>
 * Note: Before adding a further type of permission ask yourself if it is really necessary for general use.
 * </p>
 */
enum Permission {
    JobRead('hudson.model.Item.Read'),
    JobBuild('hudson.model.Item.Build'),
    JobCancel('hudson.model.Item.Cancel')

    String permission

    Permission(String permission) {
        this.permission = permission
    }
}
