# To build use: docker build -t webpack-dev -f docker/webpack/Dockerfile .
FROM node:latest

WORKDIR /teamvault
#COPY package.json yarn.lock* ./

COPY . .
RUN yarn install
RUN yarn add --dev @babel/plugin-syntax-dynamic-import
RUN mkdir -p /teamvault/teamvault/

EXPOSE 3000

ENTRYPOINT ["yarn","build"]