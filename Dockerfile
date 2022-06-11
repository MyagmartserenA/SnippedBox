FROM golang:1.16-alpine

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .
RUN go build /app/cmd/web

EXPOSE 8000

CMD [ "./web" ]