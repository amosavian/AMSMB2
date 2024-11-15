FROM swift:6.0

# Create app directory
RUN mkdir -p /usr/src/app

# Change working dir to /usr/src/app
WORKDIR /usr/src/app

VOLUME /usr/src/app

COPY AMSMB2 ./AMSMB2
COPY AMSMB2Tests ./AMSMB2Tests
COPY Package.swift ./
COPY Package@swift-6.0.swift ./

ENTRYPOINT swift test
