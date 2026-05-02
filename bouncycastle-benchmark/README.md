Build the project:

```
mvn clean package
```

Run the benchmarks and export the results to a JSON file:

```
java -jar target/bouncycastle-benchmark-1.0-SNAPSHOT.jar -rf json -rff results.json
```
