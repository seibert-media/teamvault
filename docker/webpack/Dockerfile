# To build use: docker build -t webpack-dev -f docker/webpack/Dockerfile .
FROM node:latest
WORKDIR /teamvault

COPY package.json yarn.lock* ./
RUN yarn install

COPY . .
RUN yarn add --dev @babel/plugin-syntax-dynamic-import
RUN yarn add webpack webpack-dev-server --dev
RUN mkdir -p /teamvault/teamvault/
#RUN npx webpack --config webpack.dev.js
RUN npx webpack --config webpack.dev.js --json > /teamvault/teamvault/webpack-stats.json
EXPOSE 3000
ENTRYPOINT ["yarn", "serve"]