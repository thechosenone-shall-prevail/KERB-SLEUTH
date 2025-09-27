# Sample Test Data

This directory contains synthetic test data for kerb-sleuth testing.

## Files:
- **users_small.csv**: Sample Active Directory user export
- **krb_events_small.json**: Sample Kerberos event logs

## Test Accounts:
- **backupsvc**: AS-REP vulnerable (DoesNotRequirePreAuth=True)
- **sqlsvc**: Kerberoastable (has SQL Server SPNs)
- **websvc**: Kerberoastable (has HTTP SPNs)
- **adminuser**: AS-REP vulnerable admin account
- **machine01$**: Machine account (should be filtered)
- **disableduser**: Disabled account (should be filtered)
