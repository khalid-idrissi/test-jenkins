pipeline {
    agent any
    environment {
		netboxtoken = credentials('netboxtoken')
		tokenpywire = credentials('tokenpywire')
    }
    stages {
        stage('Intsall Packages') {
            steps {
				echo "Intsall Packages"
				bat 'pip install requests'
				bat 'pip install slugify'
            }
        }
		stage('Get Python Version'){
			steps {
                script {
                    def pythonVersion = bat(script: 'python --version', returnStdout: true).trim()
                    echo "Python version: ${pythonVersion}"
                }
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

