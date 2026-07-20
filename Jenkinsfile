pipeline {
    agent any

    environment {
        SONAR_SCANNER_HOME = tool 'SonarScanner'
    }

    stages {
        stage('Checkout Code') {
            steps {
                echo 'Checking out source code...'
                checkout scm
            }
        }

        stage('SonarQube Code Analysis') {
            steps {
                withSonarQubeEnv('SonarQube-Server') {
                    sh """
                        ${SONAR_SCANNER_HOME}/bin/sonar-scanner \
                        -Dsonar.projectKey=ai-threat-detection \
                        -Dsonar.sources=. \
                        -Dsonar.host.url=http://127.0.0.1:9000
                    """
                }
            }
        }

        stage('Trivy Image Scan') {
            steps {
                echo 'Scanning Flask app image for vulnerabilities...'
                sh 'trivy image secure-flask-app:latest || true'
            }
        }

        stage('OWASP ZAP DAST Scan') {
            steps {
                echo 'Running ZAP baseline scan against OWASP Juice Shop...'
                sh '''
                    docker run --rm \
                      -v $(pwd):/zap/wrk/:rw \
                      -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                      -t http://127.0.0.1:3000 \
                      -r zap_report.html || true
                '''
            }
        }
    }
}
