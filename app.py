import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, get_flashed_messages, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired
from datetime import datetime
import pandas as pd




app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db?mode=rw'
db = SQLAlchemy(app)



class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(20), nullable=False)
    login = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.group_id'))
    
    group = db.relationship('Group', back_populates='users')
    user_tests = db.relationship('UserTest', back_populates='user')


class Group(db.Model):
    group_id = db.Column(db.Integer, primary_key=True)
    group_name = db.Column(db.String(20), nullable=False)
    
    users = db.relationship('User', back_populates='group')
    tests = db.relationship('Test', back_populates='group')


class Test(db.Model):
    test_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    group_id = db.Column(db.Integer, db.ForeignKey('group.group_id'))
    
    group = db.relationship('Group', back_populates='tests')
    questions = db.relationship('Question', back_populates='test')


class Question(db.Model):
    question_id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.test_id'))
    question_text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.Enum('одиночный выбор', 'множественный выбор'), nullable=False)
    image_url = db.Column(db.String(255))
    
    test = db.relationship('Test', back_populates='questions')
    answers = db.relationship('Answer', back_populates='question')


class Answer(db.Model):
    answer_id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.question_id'))
    answer_text = db.Column(db.String(255), nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)
    
    question = db.relationship('Question', back_populates='answers')

#о том, как пользователь прошел тест.
class UserTest(db.Model):
    user_test_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))
    test_id = db.Column(db.Integer, db.ForeignKey('test.test_id'))
    score = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime)
    
    user = db.relationship('User', back_populates='user_tests')
    test = db.relationship('Test')

#ответ пользователя на конкретный вопрос теста
class UserAnswer(db.Model):
    user_answer_id = db.Column(db.Integer, primary_key=True)
    user_test_id = db.Column(db.Integer, db.ForeignKey('user_test.user_test_id'))
    question_id = db.Column(db.Integer, db.ForeignKey('question.question_id'))
    selected_answer_id = db.Column(db.Integer, db.ForeignKey('answer.answer_id'))
    
    user_test = db.relationship('UserTest')
    question = db.relationship('Question')
    selected_answer = db.relationship('Answer')



@app.before_request
def create_admin():
    if User.query.filter_by(login='admin').first() is None:
        admin = User(user_name='Администратор', login='admin', password=generate_password_hash('admin'))
        db.session.add(admin)
        db.session.commit()

@app.route("/")
def index():
    return render_template('index.html')


@app.route("/login", methods=["POST"])
def login():
    login = request.form.get("login")
    password = request.form.get("password")
    
    user = User.query.filter_by(login=login).first()
    
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.user_id 
        return redirect(url_for('profile'))  
    else:
        flash("Неверный логин или пароль")
        return redirect(url_for('index'))


@app.route("/profile")
def profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])

    
    if user.login != 'admin':
        user_group = user.group
        available_tests = Test.query.filter_by(group_id=user.group_id).all()
    else:
        user_group = None
        available_tests = []

    return render_template('profile.html', user=user, user_group=user_group, available_tests=available_tests)


@app.route("/logout")
def logout():
    session.pop('user_id', None)  
    return redirect(url_for('index'))


def admin_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        user = User.query.get(session['user_id'])
        if user.login != 'admin':
            flash("Доступ запрещен")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper



@app.route("/test/<int:test_id>", methods=["GET", "POST"])
def test(test_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])
    test = Test.query.get(test_id)

    
    user_test = UserTest.query.filter_by(user_id=user.user_id, test_id=test.test_id).first()

    if user_test:
        # Если пользователь уже проходил тест, перенаправляем на страницу результатов
        return redirect(url_for('results', user_test_id=user_test.user_test_id))

    if request.method == "POST":
        user_test = UserTest(user_id=user.user_id, test_id=test.test_id)
        db.session.add(user_test)
        db.session.commit()

        correct_answers = 0
        for question in test.questions:
            if question.question_type == 'множественный выбор':
                
                correct_answer_ids = {answer.answer_id for answer in question.answers if answer.is_correct}
                selected_answer_ids = {int(request.form.get(f'question_{question.question_id}_{i}')) for i in range(1, len(question.answers) + 1) if request.form.get(f'question_{question.question_id}_{i}')}

                
                if selected_answer_ids == correct_answer_ids and len(selected_answer_ids) == len(correct_answer_ids):
                    correct_answers += 1

                
                for selected_answer_id in selected_answer_ids:
                    user_answer = UserAnswer(
                        user_test_id=user_test.user_test_id,
                        question_id=question.question_id,
                        selected_answer_id=selected_answer_id
                    )
                    db.session.add(user_answer)


            elif question.question_type == 'одиночный выбор':
                selected_answer_id = request.form.get(f'question_{question.question_id}')
                if selected_answer_id:
                    selected_answer = Answer.query.get(selected_answer_id)
                    if selected_answer and selected_answer.is_correct:
                        correct_answers += 1
                    user_answer = UserAnswer(
                        user_test_id=user_test.user_test_id,
                        question_id=question.question_id,
                        selected_answer_id=selected_answer_id
                    )
                    db.session.add(user_answer)

        user_test.score = correct_answers
        user_test.completed_at = datetime.now()
        db.session.commit()
        return redirect(url_for('results', user_test_id=user_test.user_test_id)) 

    questions = test.questions
    return render_template('test.html', user=user, test=test, questions=questions)


@app.route("/results/<int:user_test_id>")
def results(user_test_id):
    user_test = UserTest.query.get(user_test_id)
    if not user_test:
        return "Test not found", 404

    test = user_test.test
    user_answers = UserAnswer.query.filter_by(user_test_id=user_test_id).all()
    user_answers_dict = {}
    for user_answer in user_answers:
      if user_answer.question_id not in user_answers_dict:
          user_answers_dict[user_answer.question_id] = []
      user_answers_dict[user_answer.question_id].append(user_answer.selected_answer_id)

    return render_template("results.html", user_test=user_test, test=test, user_answers=user_answers_dict, Answer=Answer)





class UserCreationForm(FlaskForm):
    user_name = StringField('Имя пользователя', validators=[DataRequired()])
    login = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    group_id = SelectField('Группа', coerce=int)
    submit = SubmitField('Создать пользователя')

@app.route('/create_user', methods=['GET', 'POST'])
@admin_required
def create_user():
    form = UserCreationForm()
    form.group_id.choices = [(g.group_id, g.group_name) for g in Group.query.all()]
    
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            user_name=form.user_name.data,
            login=form.login.data,
            password=hashed_password,
            group_id=form.group_id.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Пользователь успешно создан!', 'success')
        return redirect(url_for('create_user'))

    return render_template('create_user.html', form=form)



@app.route("/create_test", methods=['POST', 'GET'])
@admin_required
def create_test():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        group_id = request.form['group_id']

        new_test = Test(title=title, description=description, group_id=group_id)
        
        try:
            db.session.add(new_test)
            db.session.commit()
            return redirect('/profile')
        except Exception as e:
            return f'Произошла ошибка при добавлении теста: {e}'
    
    groups = Group.query.all()
    return render_template('create_test.html', groups=groups)


UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'img')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/create_question/<int:test_id>", methods=['POST', 'GET'])
@admin_required
def create_question(test_id):
    test = Test.query.get_or_404(test_id)
    
    if request.method == 'POST':
        try:
            question_text = request.form['question_text']
            question_type = request.form['question_type']

            
            image_url = None
            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)  
                    image_url = f'img/{filename}'  

            new_question = Question(question_text=question_text, question_type=question_type, image_url=image_url, test_id=test_id)
            
            
            db.session.add(new_question)
            db.session.commit()  
            
            
            answers = request.form.getlist('answers')
            for i, answer_text in enumerate(answers):
                is_correct = request.form.get(f'is_correct_{i}') == '1'  
                new_answer = Answer(answer_text=answer_text, is_correct=is_correct, question_id=new_question.question_id)
                db.session.add(new_answer)

            db.session.commit()  
            return redirect('/profile')  
            
        except Exception as e:
            return f'Произошла ошибка при добавлении вопроса: {e}'
    
    return render_template('create_question.html', test=test)



@app.route('/view_test/<int:test_id>')
def view_test(test_id):
    test = Test.query.get(test_id)
    questions = Question.query.filter_by(test_id=test_id).all()
    
    return render_template('view_test.html', test=test, questions=questions)


@app.route("/edit_answer/<int:answer_id>", methods=['GET', 'POST'])
@admin_required
def edit_answer(answer_id):
    answer = Answer.query.get_or_404(answer_id)

    if request.method == 'POST':
        try:
            answer.answer_text = request.form['answer_text']
            answer.is_correct = 'is_correct' in request.form  # Проверяем, отмечен ли ответ как правильный

            db.session.commit()
            return redirect(url_for('view_test', test_id=answer.question.test_id))  
        except Exception as e:
            return f'Произошла ошибка при редактировании ответа: {e}'

    return render_template('edit_answer.html', answer=answer)


@app.route("/edit_question/<int:question_id>", methods=['GET', 'POST'])
@admin_required
def edit_question(question_id):
    question = Question.query.get_or_404(question_id)
    
    if request.method == 'POST':
        try:
            question.question_text = request.form['question_text']
            question.question_type = request.form['question_type']
            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    question.image_url = f'img/{filename}'

            db.session.commit()
            return redirect('/view_test/{}'.format(question.test_id))
        except Exception as e:
            return f'Произошла ошибка при редактировании вопроса: {e}'

    return render_template('edit_question.html', question=question)




@app.route("/group")
@admin_required
def group():
    groups = Group.query.all()
    return render_template('group.html', groups=groups)


@app.route("/create_group", methods=['POST','GET'])
@admin_required
def create_group():
    if request.method == 'POST':
        group_name = request.form['group_name']

        create_group = Group(group_name=group_name)

        try:
            db.session.add(create_group)
            db.session.commit()
            return redirect('/profile')
        except:
            return 'При добавлении группы произошла ошибка'
    else:
        return render_template('create_group.html')
    

@app.route("/group/<int:group_id>")
@admin_required
def group_tests(group_id):
    group = Group.query.get_or_404(group_id)
    tests = Test.query.filter_by(group_id=group_id).all()
    return render_template('group_tests.html', group=group, tests=tests)



@app.route("/admin_results")
@admin_required
def admin_results():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = db.session.query(UserTest).join(User).join(Group).join(Test)

    # Фильтрация по дате, если даты указаны
    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        query = query.filter(UserTest.completed_at >= start_date)

    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d')
        query = query.filter(UserTest.completed_at <= end_date)

    results = query.all()

    question_counts = {
        test.test_id: len(test.questions) for test in db.session.query(Test).options(db.orm.joinedload(Test.questions)).all()
    }

    return render_template('admin_results.html', results=results, question_counts=question_counts)


@app.route("/export_results")
@admin_required
def export_results():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    query = db.session.query(UserTest).join(User).join(Group).join(Test)

    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        query = query.filter(UserTest.completed_at >= start_date)
    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d')
        query = query.filter(UserTest.completed_at <= end_date)

    results = query.all()
    question_counts = {test.test_id: len(test.questions) for test in db.session.query(Test).options(db.orm.joinedload(Test.questions)).all()}

    
    data = []
    for result in results:
        data.append({
            'Имя пользователя': result.user.user_name,
            'Логин': result.user.login,
            'Группа обучения': result.user.group.group_name,
            'Тест': result.test.title,
            'Количество баллов': f"{result.score} из {question_counts[result.test.test_id]}",
            'Дата прохождения теста': result.completed_at.strftime('%d-%m-%Y %H:%M') if result.completed_at else 'Не завершён'
        })

    
    df = pd.DataFrame(data)
    output_file = "результаты_тестов.xlsx"
    df.to_excel(output_file, index=False)

    return send_file(output_file, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
