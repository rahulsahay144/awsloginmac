# awsloginmac


awsloginmac provides a way to use federated login to AWS and store the AWS creadentials on local file system to make AWS CLI work

## Update the environment configs
```
# Environment Variables
env:
    identity_provider_url: https://xxx.company.com/sps/...
    identity_provider_form_submit_url: https://xxx.company.com/pkmslogin.form
    http_proxy: http://%s:%s@xxx.company.com:8080
```

## Generate a Binary 

cd to cloned directory 
```
$ go install 
$ go build 
```

and then 
```
$ ./awsloginmac
```
Once the Binary is generated, you can just double click on the binary and run. Binary can also be distributed
