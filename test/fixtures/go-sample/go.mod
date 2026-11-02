module example.invalid/app

go 1.22

require (
	github.com/EvilCorp/beacon v1.0.0
	github.com/clean/strutil v0.2.0 // indirect
	github.com/missing/mod v1.0.0 // depthreat-ignore[network/*]
	github.com/old/name v1.0.0
)

require example.invalid/local v0.0.0

replace example.invalid/local => ../local

replace github.com/old/name v1.0.0 => github.com/new/name v1.2.3
