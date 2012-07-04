define backuppc::client::exclude ($exclude) {
  include backuppc::params
  include backuppc::client::params

  if ! is_array($exclude) {
   fail("exclude must be a list")
  }

  @@concat::fragment { "backuppc_exclude_${::fqdn}_${name}":
    target  => "${topdir}/pc/${::fqdn}/exclude.list",
    content => inline_template("<%= exclude.join('\n') %>"),
    tag     => "backuppc_exclude_${::domain}"
  }
}