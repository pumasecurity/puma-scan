FROM microsoft/dotnet:2.1-sdk

# Create directory for the source code
RUN mkdir /source

# Directory for the results
RUN mkdir /results

# Install puma into the image
COPY ./Puma.Security.Rules/bin/Release/Puma.Security.Rules.2.0.1.nupkg /tools
COPY /Docker/pumascan.sh /tools

WORKDIR /tools

# NO IDEA HOW TO PASS ARGES INTO THIS SCRIPT FROM DOCKER COMMAND??
ENTRYPOINT ["pumascan.sh", "$ARGS"]