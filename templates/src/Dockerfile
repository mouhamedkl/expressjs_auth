FROM node:16

WORKDIR /app

COPY . .

RUN npm install

EXPOSE  {{PORT}}

CMD ["node", "server.js"]
