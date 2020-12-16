Process
=======

## Set up Swagger on computer
- install swagger (mac)

      brew install swagger

- set environment variables according to your environment:

      ```
      For the system Java wrappers to find this JDK, symlink it with
        sudo ln -sfn /usr/local/opt/openjdk/libexec/openjdk.jdk /Library/Java/JavaVirtualMachines/openjdk.jdk

      openjdk is keg-only, which means it was not symlinked into /usr/local,
      because it shadows the macOS `java` wrapper.

      If you need to have openjdk first in your PATH run:
        echo 'export PATH="/usr/local/opt/openjdk/bin:$PATH"' >> ~/.zshrc

      For compilers to find openjdk you may need to set:
        export CPPFLAGS="-I/usr/local/opt/openjdk/include"
      ```

## Build InsightVM Swagger client
- grab swagger definition

      mkdir api_client
      curl https://help.rapid7.com/insightvm/en-us/api/api.json -o api_client/api.json

- add basic auth to all security: []

  use your editor to find 
  
      "security": [] 
  
  and change it to:

      "security": [
          {
              "Basic": []
          }
      ]

- generate code

      cd swagger_client
      swagger-codegen generate -i /path/to/swagger.json -l python

- install said package 

      cd swagger_client
      pip install -e .


- [create](https://insight.rapid7.com/platform#/apiKeyManagement/user) user that has access to all the sites needed

    