FROM untangleinc/ngfw:base
MAINTAINER Sebastien Delafond <sdelafond@gmail.com>

RUN apt-get update -q
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y untangle-classd

EXPOSE 8123

CMD classd -F -D
