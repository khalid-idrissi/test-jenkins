pipeline {
    agent any
    environment {
        netboxtoken = credentials('netboxtoken')
        tokenpywire = credentials('tokenpywire')
    }
    stages {
        stage('Install Packages') {
            steps {
                echo "Install Packages"
            }
        }
        stage('Test') {
            steps {
                echo 'testing'
                bat "python jenkins.py ${netboxtoken} ${tokenpywire}"
            }
        }
    }
}

