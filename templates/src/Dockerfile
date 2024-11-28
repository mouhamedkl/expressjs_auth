FROM node:16

WORKDIR /app

COPY package.json .
COPY .env .

RUN npm install

COPY . .

EXPOSE  {{PORT}}

CMD ["node", "server.js"]
