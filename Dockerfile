FROM ubuntu

# Download and install necessary packages
RUN apt-get update
RUN apt-get install -y ntpdate
RUN apt-get install -y libssl-dev
RUN apt-get install -y curl
RUN apt remove nodejs
RUN apt remove nodejs-doc
RUN apt-get install -y ca-certificates curl gnupg; \
    mkdir -p /etc/apt/keyrings; \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
     | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg; \
    NODE_MAJOR=20; \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" \
     > /etc/apt/sources.list.d/nodesource.list; \
    apt-get -qy update; \
    apt-get -qy install nodejs;
RUN apt-get install -y aptitude
RUN aptitude install -y npm
RUN npm install -g yarn

# Download and configure anypoint-cli
ENV PUPPETEER_SKIP_DOWNLOAD=true
RUN npm install -g anypoint-cli-v4

# Get args from github Action secrets/varialbes and set env variables
ARG AWS_ACCESS_KEY
ARG AWS_SECRET_KEY
ARG AWS_REGION
ARG ANYPOINT_CLIENT_ID
ARG ANYPOINT_CLIENT_SECRET
ARG ANYPOINT_ORG_ID
ARG ANYPOINT_ENV
ARG AWS_SNS_TOPIC_ARN
ENV AWS_ACCESS_KEY=$AWS_ACCESS_KEY
ENV AWS_SECRET_KEY=$AWS_SECRET_KEY
ENV AWS_REGION=$AWS_REGION
ENV ANYPOINT_CLIENT_ID=$ANYPOINT_CLIENT_ID
ENV ANYPOINT_CLIENT_SECRET=$ANYPOINT_CLIENT_SECRET
ENV ANYPOINT_ORG=$ANYPOINT_ORG_ID
ENV ANYPOINT_ENV=$ANYPOINT_ENV
ENV AWS_SNS_TOPIC_ARN=$AWS_SNS_TOPIC_ARN

# Set HOME environment variable
ENV HOME="~/"

# Copy the script and make it executable
COPY main.sh "~/"
COPY aws4.js ${LAMBDA_RUNTIME_DIR}
COPY lru.js ${LAMBDA_RUNTIME_DIR}
COPY javascript_util.js ${LAMBDA_RUNTIME_DIR}
RUN ["chmod", "+x", "~/main.sh"]
ENTRYPOINT ["~/main.sh"]