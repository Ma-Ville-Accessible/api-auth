FROM node:18-alpine

WORKDIR /app

ADD . /app

EXPOSE 4000

CMD ["npm", "run", "start:prod"]