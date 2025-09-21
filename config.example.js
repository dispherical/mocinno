module.exports = {
  ldap: {
    url: 'ldaps://',
    tlsOptions: {
      rejectUnauthorized: false,
      servername: 'identity.hackclub.app',
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2'
    },
    bindDN: 'cn=ldap-service,ou=users,dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app',
    bindPassword: '',
    baseDN: 'ou=users,dc=ldap,dc=secure,dc=vm,dc=hackclub,dc=app'
  },
  authentik: {
    url: 'https://identity.hackclub.app',
    token: ''
  },
  all_guest_mode: false,
  is_production: false,
  new_user_script: "",
  disable_signups: false,
  smtp: {
    host: 'hackclub.app',
    port: 587,
    secure: false,
    from: '"Hack Club Nest" <registration@hackclub.app>',
    auth: {
      user: '',
      pass: ''
    }
  },
  hostname: "hackclub.app"
}
