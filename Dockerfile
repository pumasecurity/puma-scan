FROM microsoft/dotnet:2.2.2-sdk

# Create directory for the source code
RUN mkdir /source

# Directory for the results
RUN mkdir /results

# Directory for the puma tools
RUN mkdir /tools

# Install puma into the image
COPY ./Puma.Security.Rules/bin/Release/Puma.Security.Rules.2.1.0.nupkg /tools
COPY ./pumascan.sh /tools

WORKDIR /tools

# TODO: PASS ARGES FROM DOCKER RUN INTO THIS SCRIPT AS ARGS
ENTRYPOINT ["pumascan.sh", "$ARGS"]